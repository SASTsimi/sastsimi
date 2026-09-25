from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest

from sastsimi.config.user_config import SimpleExecutionProfile, SimpleToolBinding
from sastsimi.simple_runtime.application import SimpleAnalysisRequest
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.bootstrap_stages import (
    DirectHypothesisBootstrap,
    DirectStaticBootstrap,
    ProcessResult,
)
from sastsimi.simple_runtime.models import CheckpointIdentity
from sastsimi.simple_runtime.provider import SimpleLLMCallResult


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
            (root / "SECURITY.md").write_text(
                "# Security Policy\n\nConfiguration options are not vulnerabilities.\n",
                encoding="utf-8",
            )
        elif argv[1:3] == ("rev-parse", "HEAD"):
            return ProcessResult(0, ("a" * 40).encode(), b"")
        elif argv[1:3] == ("ls-files", "-z"):
            return ProcessResult(0, b"app.py\0requirements.txt\0SECURITY.md\0", b"")
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


def _profile(tmp_path: Path) -> SimpleExecutionProfile:
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


class _Client:
    async def call(
        self,
        *,
        prompt: bytes,
        output_schema: Mapping[str, Any],
        timeout_ms: int,
    ) -> SimpleLLMCallResult:
        del prompt, output_schema, timeout_ms
        return SimpleLLMCallResult(
            value={
                "hypotheses": [
                    {
                        "statement": "user input reaches db.execute unparameterised",
                        "vulnerability_type_candidates": ["SQLI"],
                        "target_locations": [
                            {"file_path": "app.py", "start_line": 2, "end_line": 2}
                        ],
                        "suspected_path": [
                            {
                                "file_path": "app.py",
                                "start_line": 2,
                                "end_line": 2,
                                "role": "sink",
                            }
                        ],
                        "observed_facts": ["no sanitizer"],
                        "restrictions": [],
                        "assumptions": [],
                        "falsification_questions": ["Is the value parameterised?"],
                        "validation_checks": ["Send a quote through the input."],
                        "confidence": "medium",
                        "reachability": {"who": "unknown", "evidence": ""},
                    }
                ],
                "requested_paths": [],
                "requested_ast_paths": [],
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

    seeds = await DirectHypothesisBootstrap(
        data_dir=profile.data_dir,
        client_factory=lambda _identity, _artifacts, **_options: _Client(),
    ).propose(identity, result)

    assert len(seeds) == 1
    assert seeds[0].hypothesis_id.startswith("hypothesis-")

    # The bundle no longer carries the policy text itself; a later stage
    # that needs it reads the dedicated ref the static stage recorded.
    assert bundle["security_policy_ref"]["record_id"] is None
    assert result.security_policy_ref is not None
    policy = json.loads(
        SimpleArtifactRepository(profile.data_dir, identity).read(
            result.security_policy_ref
        )
    )
    assert policy["path"] == "SECURITY.md"
    assert "Configuration options are not vulnerabilities" in policy["content"]


@pytest.mark.asyncio
async def test_static_bootstrap_leaves_the_policy_ref_unset_without_a_policy_file(
    tmp_path: Path,
) -> None:
    profile = _profile(tmp_path)
    identity = CheckpointIdentity(
        analysis_id="analysis-2",
        workspace_id="workspace-2",
        commit_id="a" * 40,
        hypothesis_id=None,
    )

    class _NoPolicyProcess(_Process):
        async def run(
            self,
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout_seconds: int,
        ) -> ProcessResult:
            outcome = await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)
            if argv[1] == "clone":
                (Path(argv[-1]) / "SECURITY.md").unlink()
            if argv[1:3] == ("ls-files", "-z"):
                return ProcessResult(0, b"app.py\0requirements.txt\0", b"")
            return outcome

    result = await DirectStaticBootstrap(
        profile=profile,
        process=_NoPolicyProcess(),
        static_material_root=tmp_path,
    ).run(
        SimpleAnalysisRequest(
            data_dir=profile.data_dir,
            repository="https://example.invalid/repo.git",
            commit="a" * 40,
        ),
        identity,
    )

    assert result.security_policy_ref is None
