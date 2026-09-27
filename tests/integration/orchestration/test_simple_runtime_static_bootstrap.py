from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from sastsimi.config.user_config import SimpleExecutionProfile, SimpleToolBinding
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime import bootstrap_stages as static_module
from sastsimi.simple_runtime.application import SimpleAnalysisRequest
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.bootstrap_stages import (
    DirectHypothesisBootstrap,
    DirectStaticBootstrap,
    ProcessResult,
    StaticCoverageBlocked,
)
from sastsimi.simple_runtime.models import CheckpointIdentity, StageFailure
from sastsimi.simple_runtime.opengrep_rule_batches import plan_rule_batches
from sastsimi.simple_runtime.provider import SimpleLLMCallResult
from sastsimi.simple_runtime.static_coverage import plan_static_coverage
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
    await bootstrap._run_opengrep(workspace, request, _identity("analysis-timeout"))

    assert expected_timeout - 1 <= process.timeouts[-1] <= expected_timeout


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
        if argv[1] == "scan" and "--output" not in argv:
            self.fallback_calls.append(tuple(argv))
            if self.fallback_fails:
                return ProcessResult(2, b"bad", b"failed")
            return ProcessResult(
                0,
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
                ).encode(),
                b"",
            )
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
            if argv[1] == "scan" and "--output" not in argv:
                self.fallback_calls.append(tuple(argv))
                targets = [arg for arg in argv if arg.startswith("file-")]
                clock[0] += 2
                return ProcessResult(
                    0,
                    json.dumps(
                        {
                            "results": [],
                            "errors": [],
                            "paths": {"scanned": targets, "skipped": []},
                        }
                    ).encode(),
                    b"",
                )
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
    files = [f"file-{index:02d}.py" for index in range(33)]
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
    assert len(slices) == 1
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
