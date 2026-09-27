from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import SimpleNamespace
from typing import Any

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
)
from sastsimi.simple_runtime.models import CheckpointIdentity, StageFailure
from sastsimi.simple_runtime.opengrep_rule_batches import plan_rule_batches
from sastsimi.simple_runtime.provider import SimpleLLMCallResult
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
                        ]
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
