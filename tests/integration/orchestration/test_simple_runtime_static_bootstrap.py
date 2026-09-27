from __future__ import annotations

import asyncio
import hashlib
import json
import subprocess
import time
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
from sastsimi.simple_runtime.application import SimpleAnalysisRequest
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.bootstrap_stages import (
    DirectHypothesisBootstrap,
    DirectStaticBootstrap,
    ProcessResult,
    StaticCoverageBlocked,
)
from sastsimi.simple_runtime.models import CheckpointIdentity, StageFailure
from sastsimi.simple_runtime.opengrep_rule_batches import (
    RuleBatchPlan,
    plan_rule_batches,
)
from sastsimi.simple_runtime.provider import SimpleLLMCallResult
from sastsimi.simple_runtime.semgrep_fallback_plan import plan_semgrep_target_chunks
from sastsimi.simple_runtime.static_coverage import (
    CoverageSlice,
    StaticCoveragePlan,
    finish_coverage,
    merge_static_candidates,
    plan_static_coverage,
)
from sastsimi.simple_runtime.store import SimpleCheckpointStore


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
                            "path": str(Path(argv[-1]) / "app.py"),
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
async def test_all_batches_use_original_config_and_full_root(tmp_path: Path) -> None:
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
        assert argv[-1] == str(profile.workspace_root / identity.workspace_id)
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
    with pytest.raises(RuntimeError, match="EXTERNAL_TOOL_TIMEOUT"):
        await bootstrap.run(_request(profile), identity)

    plan = plan_rule_batches(
        (tmp_path / "opengrep" / "rules.yml").read_bytes(),
        tool_version=profile.tools["opengrep"].version,
        executable_sha256=profile.tools["opengrep"].executable_sha256,
    )
    assert (
        store.opengrep_batch_ref(
            identity,
            _request(profile).repository,
            plan.fingerprint,
            plan.batches[0].key,
        )
        is not None
    )
    assert (
        store.opengrep_batch_ref(
            identity,
            _request(profile).repository,
            plan.fingerprint,
            plan.batches[1].key,
        )
        is None
    )

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
async def test_shared_deadline_does_not_round_up_last_batch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = _without_codeql(_profile(tmp_path)).model_copy(
        update={"max_elapsed_seconds": 2}
    )
    rule_ids = tuple(f"python.rule{index}" for index in range(4))
    _write_rules(tmp_path, rule_ids)
    process = _BatchProcess(rule_ids)
    times = iter((100.0, 100.1, 101.9))
    monkeypatch.setattr(
        static_module, "time", SimpleNamespace(monotonic=lambda: next(times))
    )
    bootstrap = DirectStaticBootstrap(
        profile=profile,
        process=process,
        store=_store(profile),
        static_material_root=tmp_path,
    )

    with pytest.raises(RuntimeError, match="^EXTERNAL_TOOL_TIMEOUT$"):
        await bootstrap.run(_request(profile), _identity("analysis-deadline"))
    assert len(process.scans) == 1
    assert process.scans[0][2] == 1


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
    await bootstrap.run(_request(profile), identity)
    plan = plan_rule_batches(
        (tmp_path / "opengrep" / "rules.yml").read_bytes(),
        tool_version=profile.tools["opengrep"].version,
        executable_sha256=profile.tools["opengrep"].executable_sha256,
    )
    ref = store.opengrep_batch_ref(
        identity, _request(profile).repository, plan.fingerprint, plan.batches[0].key
    )
    assert ref is not None
    artifacts = SimpleArtifactRepository(profile.data_dir, identity)
    path = artifacts.artifacts.path_for(ref.content_hash)
    if damage == "delete":
        path.unlink()
    else:
        path.write_bytes(b"corrupt")

    await bootstrap.run(_request(profile), identity)

    assert len(process.scans) == 3
    assert json.loads(artifacts.read(ref))["errors"] == []


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


class _Client:
    async def call(
        self,
        *,
        prompt: bytes,
        output_schema: Mapping[str, Any],
        timeout_ms: int,
        agent_name: str = "agent",
    ) -> SimpleLLMCallResult:
        del prompt, output_schema, timeout_ms, agent_name
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
    assert manifest["paths"] == ["app.py", "requirements.txt"]

    seeds = await DirectHypothesisBootstrap(
        data_dir=profile.data_dir,
        client_factory=lambda _identity, _artifacts: _Client(),
    ).propose(identity, result)

    assert not isinstance(seeds, StageFailure)
    assert len(seeds) == 1
    assert seeds[0].hypothesis_id.startswith("hypothesis-")


@pytest.mark.asyncio
async def test_opengrep_retry_rejects_stale_output(tmp_path: Path) -> None:
    class NoOutputProcess(_Process):
        async def run(
            self,
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout_seconds: int,
        ) -> ProcessResult:
            if argv[1] == "scan":
                return ProcessResult(0, b"", b"")
            return await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)

    profile = _profile(tmp_path)
    request = _request(profile)
    identity = _identity("analysis-retry")
    workspace = _ready_workspace(tmp_path, request)
    plan = plan_rule_batches(
        (tmp_path / "opengrep" / "rules.yml").read_bytes(),
        tool_version=profile.tools["opengrep"].version,
        executable_sha256=profile.tools["opengrep"].executable_sha256,
    )
    output = (
        profile.data_dir
        / "process-output"
        / "simple-static"
        / "analysis-retry"
        / f"opengrep-000-{plan.batches[0].key[:12]}.json"
    )
    output.parent.mkdir(parents=True)
    output.write_text('{"results":[{"stale":true}]}', encoding="utf-8")

    bootstrap = DirectStaticBootstrap(
        profile=profile,
        process=NoOutputProcess(),
        store=_store(profile),
        static_material_root=tmp_path,
    )
    with pytest.raises(RuntimeError, match="^OPENGREP_EXECUTION_FAILED$"):
        await bootstrap._run_opengrep(workspace, request, identity)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("profile_limit", "expected_timeout"),
    [(3600, 3600), (600, 600)],
)
async def test_opengrep_timeout_respects_hour_cap_and_profile(
    tmp_path: Path, profile_limit: int, expected_timeout: int
) -> None:
    class RecordingProcess(_Process):
        def __init__(self) -> None:
            self.timeouts: list[int] = []

        async def run(
            self,
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout_seconds: int,
        ) -> ProcessResult:
            self.timeouts.append(timeout_seconds)
            return await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)

    profile = _profile(tmp_path).model_copy(
        update={"max_elapsed_seconds": profile_limit}
    )
    process = RecordingProcess()
    bootstrap = DirectStaticBootstrap(
        profile=profile,
        process=process,
        store=_store(profile),
        static_material_root=tmp_path,
    )
    request = _request(profile)
    workspace = _ready_workspace(tmp_path, request)
    started = time.monotonic()
    await bootstrap._run_opengrep(workspace, request, _identity("analysis-timeout"))
    elapsed = time.monotonic() - started

    assert (
        max(1, expected_timeout - int(elapsed) - 1)
        <= process.timeouts[-1]
        <= expected_timeout
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
            del argv, cwd, timeout_seconds
            return ProcessResult(0, b"", b"")

    profile = _profile(tmp_path)
    repository = "https://example.invalid/project.git"
    commit = "a" * 40
    analysis_id = "analysis-retry"
    key = hashlib.sha256(f"{repository}\0{commit}".encode()).hexdigest()[:24]
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
            tmp_path / "checkout",
            profile.data_dir,
            repository,
            commit,
            analysis_id,
        )

    assert not output.exists()


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
    key = hashlib.sha256(f"{repository}\0{commit}".encode()).hexdigest()[:24]
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
        tmp_path / "checkout", profile.data_dir, repository, commit, "analysis-one"
    )
    await bootstrap._run_codeql(
        tmp_path / "checkout", profile.data_dir, repository, commit, "analysis-two"
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

    async def run(
        self, argv: Sequence[str], *, cwd: Path | None = None, timeout_seconds: int
    ) -> ProcessResult:
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
            output = Path(argv[argv.index("--output") + 1])
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(
                json.dumps(
                    {
                        "results": [
                            {
                                "check_id": "python.sql",
                                "path": "app.py",
                                "start": {"line": 1},
                            },
                            {
                                "check_id": "python.sql",
                                "path": "good.py",
                                "start": {"line": 1},
                            },
                        ],
                        "errors": (
                            [{"type": "PartialParsing", "path": "app.py"}]
                            if self.parse_warning
                            else []
                        ),
                        "paths": {"scanned": ["app.py", "good.py"], "skipped": []},
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
    tmp_path: Path, process: _AdaptiveSemgrepProcess, count: int = 129
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
    assert len(process.calls) == count
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
    assert len(process.calls) == 2
    assert finish_coverage(fixture[4], resumed).gaps[0].reason == "scan_timeout"


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


async def _seed_old_partial(
    tmp_path: Path, process: _CoverageProcess, analysis_id: str
) -> tuple[
    SimpleExecutionProfile,
    SimpleCheckpointStore,
    CheckpointIdentity,
    StaticCoverageBlocked,
]:
    bootstrap, profile, store = _coverage_bootstrap(tmp_path, process, codeql=False)
    identity = _identity(analysis_id)
    with pytest.raises(StaticCoverageBlocked) as caught:
        await bootstrap.run(_request(profile), identity)
    assert process.opengrep_calls == 1
    return profile, store, identity, caught.value


@pytest.mark.asyncio
async def test_fallback_opt_in_revalidates_old_partial_without_opengrep_rerun(
    tmp_path: Path,
) -> None:
    process = _CoverageProcess()
    old_profile, store, identity, old_blocked = await _seed_old_partial(
        tmp_path, process, "reuse-old-partial"
    )
    old_report = _coverage_from_ref(old_profile, identity, old_blocked.coverage_ref)
    assert old_report["verified_count"] == 1
    profile = _enable_semgrep_fallback(old_profile)
    bootstrap = DirectStaticBootstrap(
        profile=profile, process=process, store=store, static_material_root=tmp_path
    )
    completed = await bootstrap.run(_request(profile), identity)
    assert process.opengrep_calls == 1
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
async def test_cross_fingerprint_corrupt_partial_is_quarantined_and_rescanned(
    tmp_path: Path,
) -> None:
    process = _CoverageProcess()
    old_profile, store, identity, old_blocked = await _seed_old_partial(
        tmp_path, process, "corrupt-old-partial"
    )
    old_report = _coverage_from_ref(old_profile, identity, old_blocked.coverage_ref)
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
    old_report = _coverage_from_ref(old_profile, identity, old_blocked.coverage_ref)
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
        old_blocked.coverage_ref,
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
    profile: SimpleExecutionProfile, identity: CheckpointIdentity, ref: StoredDataRef
) -> dict[str, Any]:
    return cast(
        dict[str, Any],
        json.loads(SimpleArtifactRepository(profile.data_dir, identity).read(ref)),
    )


@pytest.mark.asyncio
async def test_opengrep_failure_blocks_even_without_applicable_file_rules(
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
                return ProcessResult(2, b"", b"scanner failed")
            return await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)

    bootstrap, profile, _store_ = _coverage_bootstrap(
        tmp_path, NoApplicableSource(), codeql=False
    )
    with pytest.raises(StaticCoverageBlocked, match="OPENGREP_EXECUTION_FAILED"):
        await bootstrap.run(_request(profile), _identity("empty-rule-failure"))


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
                output = Path(argv[argv.index("--output") + 1])
                output.parent.mkdir(parents=True, exist_ok=True)
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
                return ProcessResult(2 if self.opengrep_calls == 1 else 0, b"", b"")
            return await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)

    process = FailedThenSuccessful(parse_warning=False)
    bootstrap, profile, _store_ = _coverage_bootstrap(tmp_path, process, codeql=False)
    identity = _identity("nonzero-cache")
    with pytest.raises(StaticCoverageBlocked, match="OPENGREP_EXECUTION_FAILED"):
        await bootstrap.run(_request(profile), identity)
    await bootstrap.run(_request(profile), identity)
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
    with pytest.raises(StaticCoverageBlocked) as first:
        await bootstrap.run(request, identity)
    first_report = _coverage_from_ref(profile, identity, first.value.coverage_ref)
    assert first_report["verified_count"] == 1
    previous = next(
        item
        for item in store.list_static_scan_attempts(
            identity, request.repository, first_report["fingerprint"]
        )
        if item.tool == "opengrep"
    )
    assert previous.raw_ref is not None

    with pytest.raises(StaticCoverageBlocked) as second:
        await bootstrap.run(request, identity)
    second_report = _coverage_from_ref(profile, identity, second.value.coverage_ref)
    assert process.opengrep_calls == 2
    assert second_report["verified_count"] == 1
    assert second_report["gaps"][0]["path"] == "app.py"
    latest = next(
        item
        for item in store.list_static_scan_attempts(
            identity, request.repository, second_report["fingerprint"]
        )
        if item.tool == "opengrep"
    )
    assert latest.raw_ref == previous.raw_ref


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
    with pytest.raises(StaticCoverageBlocked) as first:
        await bootstrap.run(request, identity)
    first_report = _coverage_from_ref(profile, identity, first.value.coverage_ref)
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
    latest = next(
        item
        for item in store.list_static_scan_attempts(
            identity, request.repository, coverage["fingerprint"]
        )
        if item.tool == "opengrep"
    )
    assert latest.raw_ref == previous.raw_ref
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
    with pytest.raises(StaticCoverageBlocked):
        await bootstrap.run(request, identity)
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
                                "scanned": ["app.py", "good.py"],
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
    with pytest.raises(StaticCoverageBlocked):
        await bootstrap.run(request, identity)
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
async def test_resume_reuses_located_list_form_partial_parsing(
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
    with pytest.raises(StaticCoverageBlocked) as first:
        await bootstrap.run(request, identity)
    report = _coverage_from_ref(profile, identity, first.value.coverage_ref)
    assert report["expected_count"] == 2
    assert report["verified_count"] == 0
    assert {gap["path"] for gap in report["gaps"]} == {"app.py", "good.py"}
    assert any(
        "app.py" in call and "good.py" in call for call in process.fallback_calls
    )
    with pytest.raises(StaticCoverageBlocked):
        await bootstrap.run(request, identity)
    assert process.opengrep_calls == 1


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

    process = PartialFirst()
    bootstrap, profile, store = _coverage_bootstrap(tmp_path, process, codeql=False)
    identity = _identity("locked-retry-output")
    request = _request(profile)
    with pytest.raises(StaticCoverageBlocked) as first:
        await bootstrap.run(request, identity)
    first_report = _coverage_from_ref(profile, identity, first.value.coverage_ref)
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
    with pytest.raises(StaticCoverageBlocked) as second:
        await bootstrap.run(request, identity)
    second_report = _coverage_from_ref(profile, identity, second.value.coverage_ref)
    assert second_report["verified_count"] == 1
    assert process.opengrep_calls == 1
    latest = next(
        item
        for item in store.list_static_scan_attempts(
            identity, request.repository, second_report["fingerprint"]
        )
        if item.tool == "opengrep"
    )
    assert latest.raw_ref == previous.raw_ref


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
    with pytest.raises(StaticCoverageBlocked) as caught:
        await bootstrap.run(_request(profile), identity)
    bundle = _coverage_from_ref(profile, identity, caught.value.bundle_ref)
    assert bundle["opengrep_findings"][0]["path"] == "app.py"
    assert bundle["opengrep_findings"][0]["scan_incomplete"] is True


@pytest.mark.asyncio
async def test_codeql_runs_after_opengrep_partial_parse(tmp_path: Path) -> None:
    process = _CoverageProcess()
    bootstrap, profile, _ = _coverage_bootstrap(tmp_path, process)
    identity = _identity("analysis-codeql-after-warning")
    with pytest.raises(
        StaticCoverageBlocked, match="STATIC_COVERAGE_INCOMPLETE"
    ) as caught:
        await bootstrap.run(_request(profile), identity)
    assert process.codeql_calls == 1
    report = _coverage_from_ref(profile, identity, caught.value.coverage_ref)
    assert report["expected_count"] == 2
    assert report["verified_count"] == 1
    assert report["gaps"][0]["path"] == "app.py"
    bundle = _coverage_from_ref(profile, identity, caught.value.bundle_ref)
    assert bundle["codeql_executed"] is True
    assert bundle["ast_summary"]["kind"] == "simple_python_ast"


@pytest.mark.asyncio
async def test_semgrep_closes_only_failed_file_rule_pairs(tmp_path: Path) -> None:
    process = _CoverageProcess()
    bootstrap, profile, _ = _coverage_bootstrap(
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
    assert {hit["engine"] for hit in bundle["opengrep_findings"]} == {
        "opengrep",
        "semgrep",
    }


@pytest.mark.asyncio
async def test_codeql_survives_fallback_failure(tmp_path: Path) -> None:
    process = _CoverageProcess(fallback_fails=True)
    bootstrap, profile, store = _coverage_bootstrap(tmp_path, process, semgrep=True)
    identity = _identity("analysis-fallback-failed")
    with pytest.raises(
        StaticCoverageBlocked, match="SEMGREP_EXECUTION_FAILED"
    ) as caught:
        await bootstrap.run(_request(profile), identity)
    assert process.codeql_calls == 1
    bundle = _coverage_from_ref(profile, identity, caught.value.bundle_ref)
    assert bundle["codeql_executed"] is True
    assert len(bundle["tool_result_refs"]) >= 3
    report = _coverage_from_ref(profile, identity, caught.value.coverage_ref)
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
    assert (
        SimpleArtifactRepository(profile.data_dir, identity).read(attempt.raw_ref)
        == b"bad"
    )


@pytest.mark.asyncio
async def test_codeql_failure_retains_ast_and_opengrep_evidence(tmp_path: Path) -> None:
    process = _CoverageProcess(parse_warning=False, codeql_fails=True)
    bootstrap, profile, _ = _coverage_bootstrap(tmp_path, process)
    identity = _identity("analysis-codeql-failed")
    with pytest.raises(StaticCoverageBlocked, match="CODEQL_ANALYZE_FAILED") as caught:
        await bootstrap.run(_request(profile), identity)
    bundle = _coverage_from_ref(profile, identity, caught.value.bundle_ref)
    assert bundle["ast_summary"]["facts"]
    assert bundle["opengrep_findings"]
    assert bundle["codeql_executed"] is False
    assert len(bundle["tool_result_refs"]) >= 2


@pytest.mark.asyncio
async def test_ast_parse_errors_and_truncation_are_disclosed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    process = _CoverageProcess(parse_warning=False, invalid_python=True)
    bootstrap, profile, _ = _coverage_bootstrap(tmp_path, process, codeql=False)
    monkeypatch.setattr(static_module, "_MAX_FACTS", 1)
    identity = _identity("analysis-ast-errors")
    result = await bootstrap.run(_request(profile), identity)
    bundle = _coverage_from_ref(profile, identity, result.static_bundle_ref)
    report = _coverage_from_ref(
        profile, identity, StoredDataRef.model_validate(bundle["static_coverage_ref"])
    )
    assert report["ast_parse_error_count"] == 1
    assert report["ast_truncated"] is True


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
    assert first.static_bundle_ref == second.static_bundle_ref


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
    with pytest.raises(StaticCoverageBlocked, match="STATIC_COVERAGE_INCOMPLETE"):
        await bootstrap.run(_request(profile), identity)
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
    with pytest.raises(StaticCoverageBlocked, match="SEMGREP_TOOL_UNAVAILABLE"):
        await bootstrap.run(_request(profile), identity)
    assert len(process.fallback_calls) == 1


@pytest.mark.asyncio
async def test_semgrep_fallback_chunks_share_one_elapsed_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = [100.0]

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
                targets = [arg for arg in argv if arg.startswith("file-")]
                clock[0] += 2
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
    profile = profile.model_copy(update={"max_elapsed_seconds": 1})
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
        static_module, "time", SimpleNamespace(monotonic=lambda: clock[0])
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
    assert len(process.fallback_calls) == 1
    assert len(slices) == 2
    assert slices[1].gap_reasons == (
        ("file-128.py", "python.sql", "EXTERNAL_TOOL_TIMEOUT"),
    )
    assert errors == ["EXTERNAL_TOOL_TIMEOUT"]


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
