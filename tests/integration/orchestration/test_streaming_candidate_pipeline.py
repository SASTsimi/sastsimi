"""Exercise the v2 producer, child queue, surface proof, and public status together.

Discovery/Hypothesis and downstream Agent/Docker responses are synthetic.
The source inventory, AST, artifacts, SQLite checkpoints, stage handlers,
orchestration, coverage, progress projection, and CLI rendering are production.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from collections import Counter
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path
from shutil import copytree
from time import perf_counter_ns
from typing import Any, cast

import pytest
from pydantic import JsonValue

from sastsimi.composition.simple_runtime_composition import (
    PublicSimpleRuntimeApplication,
)
from sastsimi.config.user_config import SimpleExecutionProfile, UserConfig
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.interfaces.cli.public import emit_public
from sastsimi.sandbox.docker_adapter import DockerCommandOutcome
from sastsimi.simple_runtime.application import (
    BatchProposalResult,
    CandidateProposalOutcome,
    HypothesisSeed,
    SimpleAnalysisApplication,
    SimpleAnalysisRequest,
    StaticBootstrapResult,
)
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.ast_facts import collect_python_ast
from sastsimi.simple_runtime.attack_surfaces import ReviewPart
from sastsimi.simple_runtime.attempt_owner import AttemptOwner, PromptByteCounts
from sastsimi.simple_runtime.bootstrap_stages import (
    DirectHypothesisBootstrap,
    SurfaceProposalResult,
)
from sastsimi.simple_runtime.candidate_batches import CandidateBatch
from sastsimi.simple_runtime.chaining import SimpleChainingStage
from sastsimi.simple_runtime.models import (
    HYPOTHESIS_STAGES,
    STAGE_VERSION,
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageFailure,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.provider import SimpleLLMCallResult
from sastsimi.simple_runtime.runner import RunOutcome, SimpleRuntimeRunner
from sastsimi.simple_runtime.scope_policy import (
    project_scope_review,
    safe_public_report,
)
from sastsimi.simple_runtime.stages import (
    ReproductionEnvironment,
    build_stage_handlers,
)
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.simple_runtime.surface_contexts import SurfaceContext

_COMMIT = "a" * 40
_SCOPE = hashlib.sha256(b"fixture-python-scope").hexdigest()
_REVIEW_PARTS: frozenset[ReviewPart] = frozenset(
    {"ENTRY", "SENSITIVE_OPERATION", "TRUST_BOUNDARY"}
)


class _StaticBootstrap:
    def __init__(self, result: StaticBootstrapResult) -> None:
        self.result = result

    async def run(
        self, _request: SimpleAnalysisRequest, _identity: CheckpointIdentity
    ) -> StaticBootstrapResult:
        return self.result


class _DiscoveryClient:
    def __init__(self) -> None:
        self.calls = 0
        self.prompt_bytes = 0

    def budget_failure(self) -> None:
        return None

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
        del output_schema, timeout_ms, owner, prompt_bytes, invocation_id
        assert agent_name == "discovery"
        self.calls += 1
        self.prompt_bytes += len(prompt)
        rows = json.loads(prompt.split(b"<CANDIDATES>")[1].split(b"</CANDIDATES>")[0])
        value: dict[str, JsonValue] = {
            "decisions": [
                {
                    "candidate_id": row["candidate_id"],
                    "status": (
                        "EXCLUDE"
                        if row["path"] == "api.py" and row["line"] == 6
                        else "INCLUDE"
                    ),
                    "reason": (
                        "The call site has a concrete source or a constant argument"
                    ),
                    "evidence": f"{row['path']}:{row['line']}",
                }
                for row in rows
            ]
        }
        return SimpleLLMCallResult(
            value=value,
            prompt_digest="a" * 64,
            output_digest=hashlib.sha256(canonical_bytes(value)).hexdigest(),
        )


class _FixtureProposer:
    def __init__(
        self,
        data_dir: Path,
        events: list[str],
        *,
        omit_storage_once: bool = False,
        incomplete_storage_review: bool = False,
    ) -> None:
        self.data_dir = data_dir
        self.events = events
        self.omit_storage_once = omit_storage_once
        self.incomplete_storage_review = incomplete_storage_review
        self.batch_calls: list[tuple[str, tuple[str, ...]]] = []
        self.surface_calls: list[tuple[str, str]] = []
        self.shared_context_bytes = 0

    async def propose(
        self, _identity: CheckpointIdentity, _static: StaticBootstrapResult
    ) -> tuple[HypothesisSeed, ...] | StageFailure:
        raise AssertionError("v2 must not use per-candidate legacy proposals")

    async def propose_page(self, *_args: object, **_kwargs: object) -> object:
        raise AssertionError("v2 must not use whole-source pages")

    async def propose_batch(
        self,
        identity: CheckpointIdentity,
        _static: StaticBootstrapResult,
        batch: CandidateBatch,
        *,
        requested_ids: tuple[str, ...] | None = None,
    ) -> BatchProposalResult:
        ids = requested_ids or batch.candidate_ids
        self.batch_calls.append((batch.path, ids))
        self.events.append(f"batch:{batch.path}")
        artifacts = SimpleArtifactRepository(self.data_dir, identity)
        self.shared_context_bytes += len(artifacts.read(batch.shared_context_ref))
        if batch.path == "storage.py" and self.omit_storage_once:
            self.omit_storage_once = False
            return BatchProposalResult(
                results={},
                missing_ids=ids,
                attempt_refs=(),
                failure=StageFailure(
                    code="HYPOTHESIS_BATCH_OUTPUT_INVALID",
                    retryable=False,
                    safe_message="The storage candidate was omitted",
                ),
            )
        result_ref = artifacts.put_json(
            {
                "kind": "simple_candidate_batch_response_v1",
                "batch_id": batch.batch_id,
                "requested_ids": ids,
                "candidate_results": [
                    {
                        "candidate_id": candidate_id,
                        "status": (
                            "HYPOTHESES" if batch.path == "api.py" else "NO_HYPOTHESIS"
                        ),
                    }
                    for candidate_id in ids
                ],
            }
        )
        results: dict[str, CandidateProposalOutcome] = {}
        for candidate_id in ids:
            seeds: tuple[HypothesisSeed, ...] = ()
            if batch.path == "api.py":
                proposal_ref = artifacts.put_prompt_proposal(
                    {
                        "kind": "simple_hypothesis_proposal",
                        "analysis_id": identity.analysis_id,
                        "hypothesis_id": "known-command-path",
                        "candidate_id": candidate_id,
                        "shared_context_ref": batch.shared_context_ref.model_dump(
                            mode="json"
                        ),
                        "qualification": {
                            "attacker_control": "YES",
                            "sensitive_operation": "YES",
                            "reachability": "YES",
                            "trust_boundary": "route argument reaches subprocess shell",
                            "evidence_locations": ["api.py:3"],
                        },
                        "proposal": {
                            "title": "Untrusted command reaches a shell",
                            "code_locations": ["api.py:3"],
                        },
                    }
                )
                seeds = (
                    HypothesisSeed(
                        hypothesis_id="known-command-path",
                        proposal_ref=proposal_ref,
                    ),
                )
            results[candidate_id] = CandidateProposalOutcome(
                status="HYPOTHESES" if seeds else "NO_HYPOTHESIS",
                reason="Concrete source and sink"
                if seeds
                else "No supported attack path",
                seeds=seeds,
                result_ref=result_ref,
            )
        return BatchProposalResult(
            results=results,
            missing_ids=(),
            attempt_refs=(result_ref,),
        )

    async def propose_surface(
        self,
        identity: CheckpointIdentity,
        static: StaticBootstrapResult,
        context: SurfaceContext,
    ) -> SurfaceProposalResult:
        artifacts = SimpleArtifactRepository(self.data_dir, identity)
        payload = json.loads(artifacts.read(context.context_ref))
        location = f"{payload['path']}:{payload['line']}"
        self.surface_calls.append((context.surface_id, location))
        self.events.append(f"surface:{location}")
        reviewed_parts: frozenset[ReviewPart] = (
            frozenset({"ENTRY"})
            if self.incomplete_storage_review and location == "storage.py:2"
            else _REVIEW_PARTS
        )
        result_ref = artifacts.put_json(
            {
                "kind": "simple_surface_hypothesis_result_v1",
                "analysis_id": identity.analysis_id,
                "surface_id": context.surface_id,
                "context_id": context.context_id,
                "part_index": context.part_index,
                "part_count": context.part_count,
                "context_hash": context.context_hash,
                "static_bundle_hash": static.static_bundle_ref.content_hash,
                "status": "NO_HYPOTHESIS",
                "reason": "Reviewed the bounded source and operation",
                "reviewed_parts": sorted(reviewed_parts),
                "evidence_locations": [location],
                "seed_ids": [],
            }
        )
        return SurfaceProposalResult(
            surface_id=context.surface_id,
            context_id=context.context_id,
            part_index=context.part_index,
            part_count=context.part_count,
            status="NO_HYPOTHESIS",
            reason="Reviewed the bounded source and operation",
            seeds=(),
            result_ref=result_ref,
            reviewed_parts=reviewed_parts,
            evidence_locations=(location,),
        )


class _FixtureRunner(SimpleRuntimeRunner):
    def __init__(
        self,
        store: SimpleCheckpointStore,
        data_dir: Path,
        root: CheckpointIdentity,
        events: list[str],
        child_started_ns: list[int] | None = None,
    ) -> None:
        self.events = events
        self.data_dir = data_dir
        self.root = root
        self.child_started_ns = child_started_ns
        chaining = SimpleChainingStage(
            store=store,
            client=_DiscoveryClient(),
            artifacts=SimpleArtifactRepository(data_dir, root),
        )
        super().__init__(store, {SimpleStage.CHAINING_DONE: chaining})

    async def resume_hypothesis(self, identity: CheckpointIdentity) -> RunOutcome:
        assert identity.hypothesis_id is not None
        if self.child_started_ns is not None:
            self.child_started_ns.append(perf_counter_ns())
        self.events.append(f"pro_con:{identity.hypothesis_id}")
        artifacts = SimpleArtifactRepository(self.data_dir, identity)
        pending = self.store.require(identity, SimpleStage.PRO_CON_DONE)
        source_refs = [ref.model_dump(mode="json") for ref in pending.input_refs]

        def evidence(role: str) -> StoredDataRef:
            result = {
                "claims": ["Fixture-only source review"],
                "evidence_refs": [pending.input_refs[0].content_hash],
                "limitations": [],
                "requested_paths": [],
            }
            return artifacts.put_json(
                {
                    "kind": f"simple_{role}_evidence",
                    "source_refs": source_refs,
                    "result": result,
                    "prompt_digest": "a" * 64,
                    "output_digest": hashlib.sha256(
                        canonical_bytes(result)
                    ).hexdigest(),
                    "attempt_id": pending.attempt_id,
                }
            )

        pro_ref = evidence("pro")
        con_ref = evidence("con")
        self.store.save_checkpoint(
            pending.model_copy(
                update={
                    "status": StageStatus.SUCCEEDED,
                    "output_refs": (pro_ref, con_ref),
                }
            )
        )
        proof_ref = artifacts.put_json(
            {"kind": "simple_verification_result", "result": {"verdict": "FALSE"}}
        )
        self.store.save_checkpoint(
            StageCheckpoint(
                identity=identity,
                stage=SimpleStage.VERIFICATION_FINAL_DONE,
                stage_version=STAGE_VERSION[SimpleStage.VERIFICATION_FINAL_DONE],
                status=StageStatus.SUCCEEDED,
                input_refs=(),
                input_hash=input_reference_hash(()),
                output_refs=(proof_ref,),
                verdict="FALSE",
            )
        )
        return RunOutcome(
            current_stage=SimpleStage.VERIFICATION_FINAL_DONE,
            status=StageStatus.SUCCEEDED,
        )


class _MeasuredHypothesisTransport:
    """Return fixed agent responses while recording actual serialized call inputs."""

    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.requests: list[tuple[str, bytes]] = []

    @staticmethod
    def _between(prompt: bytes, start: bytes, end: bytes) -> dict[str, Any] | list[Any]:
        return cast(
            dict[str, Any] | list[Any],
            json.loads(prompt.split(start, 1)[1].split(end, 1)[0]),
        )

    @staticmethod
    def _legacy_positive() -> dict[str, object]:
        return {
            "title": "Untrusted command reaches a shell",
            "vulnerability_type": "COMMAND_INJECTION",
            "summary": "A route argument reaches a subprocess shell.",
            "code_locations": ["api.py:3"],
            "source": "route argument",
            "sink": "subprocess.run(shell=True)",
            "rationale": "The visible route forwards untrusted input to the shell.",
        }

    @classmethod
    def _qualified_positive(cls) -> dict[str, object]:
        return {
            **cls._legacy_positive(),
            "qualification": {
                "attacker_control": "YES",
                "sensitive_operation": "YES",
                "reachability": "YES",
                "trust_boundary": "request argument to subprocess shell",
                "controls": "NONE",
                "preconditions": "The route is exposed to an untrusted caller",
                "evidence_locations": ["api.py:3"],
            },
        }

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
        del output_schema, timeout_ms, prompt_bytes, invocation_id
        self.requests.append((agent_name, prompt))
        if agent_name == "hypothesis":
            payload = self._between(
                prompt,
                b"<UNTRUSTED_EXACT_INPUTS>\n",
                b"\n</UNTRUSTED_EXACT_INPUTS>",
            )
            assert isinstance(payload, dict)
            focus = payload["exact_inputs"][0]["data"]["candidate_focus"]
            self.events.append(f"legacy_candidate:{focus['path']}:{focus['line']}")
            value: dict[str, object] = {
                "hypotheses": (
                    [self._legacy_positive()]
                    if focus["path"] == "api.py" and focus["line"] == 3
                    else []
                )
            }
        elif agent_name == "hypothesis_page":
            self.events.append("legacy_source_page")
            value = {"hypotheses": []}
        elif agent_name == "hypothesis_batch":
            rows = self._between(prompt, b"<CANDIDATE_ROWS>\n", b"\n</CANDIDATE_ROWS>")
            assert isinstance(rows, list) and rows
            self.events.append(f"hypothesis_batch:{rows[0]['path']}")
            value = {
                "candidate_results": [
                    {
                        "candidate_id": row["candidate_id"],
                        "status": (
                            "HYPOTHESES"
                            if row["path"] == "api.py" and row["line"] == 3
                            else "NO_HYPOTHESIS"
                        ),
                        "reason": "Reviewed the source and operation",
                        "hypotheses": (
                            [self._qualified_positive()]
                            if row["path"] == "api.py" and row["line"] == 3
                            else []
                        ),
                    }
                    for row in rows
                ]
            }
        elif agent_name == "hypothesis_surface":
            payload = self._between(
                prompt,
                b"<UNTRUSTED_EXACT_INPUTS>\n",
                b"\n</UNTRUSTED_EXACT_INPUTS>",
            )
            assert isinstance(payload, dict)
            assert owner is not None and owner.context_id is not None
            location = f"{payload['path']}:{payload['line']}"
            self.events.append(f"hypothesis_surface:{location}")
            value = {
                "surface_id": payload["surface_id"],
                "context_id": owner.context_id,
                "status": "NO_HYPOTHESIS",
                "reason": "The visible code does not support another path",
                "hypotheses": [],
                "review_evidence": [
                    {
                        "part": part,
                        "location": location,
                        "explanation": "Reviewed the bounded source context",
                    }
                    for part in sorted(_REVIEW_PARTS)
                ],
            }
        else:
            raise AssertionError(f"Unexpected synthetic agent call: {agent_name}")
        return SimpleLLMCallResult(
            value=cast(dict[str, JsonValue], value),
            prompt_digest="a" * 64,
            output_digest=hashlib.sha256(canonical_bytes(value)).hexdigest(),
        )


def _public_app(data_dir: Path) -> PublicSimpleRuntimeApplication:
    config = UserConfig(
        data_dir=data_dir,
        profile_path=data_dir / "profile.toml",
        auth_mode="API_KEY",
        provider="openai",
        model="fixture-model",
        credential_ref="env:OPENAI_API_KEY",
        execution_profile="LIGHTWEIGHT",
        max_cost_minor_units=100,
        max_tokens=1000,
        max_elapsed_seconds=3600,
        docker_network="NONE",
        enabled_tools=(),
        detected_versions={},
        setup_ready=True,
    )
    profile = SimpleExecutionProfile(
        provider_profile_ref="fixture",
        provider="openai",
        model="fixture-model",
        auth_mode="API_KEY",
        credential_ref="env:OPENAI_API_KEY",
        data_dir=data_dir,
        workspace_root=data_dir / "workspaces",
        max_cost_minor_units=100,
        max_tokens=1000,
        max_elapsed_seconds=3600,
        docker_network="NONE",
        tools={},
    )
    return PublicSimpleRuntimeApplication(config, profile)


def _fixture(
    tmp_path: Path,
    *,
    omit_storage_once: bool = False,
    incomplete_storage_review: bool = False,
    pipeline_version: int = 2,
    bulk_candidate_count: int = 0,
    committed_checkout: bool = False,
) -> tuple[
    SimpleAnalysisApplication,
    SimpleCheckpointStore,
    _DiscoveryClient,
    _FixtureProposer,
    list[str],
    Path,
]:
    data_dir = tmp_path / "data"
    workspace = data_dir / "checkout"
    workspace.mkdir(parents=True)
    sources = {
        "api.py": (
            "import subprocess\n"
            "def route(user_input):\n"
            "    subprocess.run(user_input, shell=True, check=True)\n"
            "\n"
            "def safe_constant():\n"
            "    subprocess.run(['echo', 'safe'], check=True)\n"
        ),
        "storage.py": (
            "def save(path, body):\n"
            "    with open(path, 'wb') as output:\n"
            "        output.write(body)\n"
        ),
        "helpers.py": "def format_name(name):\n    return name.strip().title()\n",
    }
    if bulk_candidate_count:
        sources["bulk.py"] = "".join(
            f"def save_{index:02d}(path):\n    open(path, 'wb')\n"
            for index in range(bulk_candidate_count)
        )
    for name, source in sources.items():
        if committed_checkout:
            (workspace / name).write_bytes(source.encode("utf-8"))
        else:
            (workspace / name).write_text(source, encoding="utf-8")
    commit = _COMMIT
    if committed_checkout:
        subprocess.run(["git", "init", "-q"], cwd=workspace, check=True)
        subprocess.run(
            ["git", "config", "core.autocrlf", "false"],
            cwd=workspace,
            check=True,
        )
        subprocess.run(
            ["git", "add", "--", *sorted(sources)], cwd=workspace, check=True
        )
        subprocess.run(
            [
                "git",
                "-c",
                "user.name=Sastsimi Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-qm",
                "Pinned fixture sources",
            ],
            cwd=workspace,
            check=True,
        )
        commit = (
            subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=workspace)
            .decode("ascii")
            .strip()
        )
    identity = CheckpointIdentity(
        analysis_id="analysis-fixture",
        workspace_id="workspace-fixture",
        commit_id=commit,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(data_dir, identity)
    result_rows = (
        ("api.py", 3, "python.command-injection"),
        ("api.py", 6, "python.command-injection"),
        ("storage.py", 2, "python.path-sink"),
    ) + tuple(
        ("bulk.py", 2 * index + 2, "python.path-sink")
        for index in range(bulk_candidate_count)
    )
    raw_ref = artifacts.put_bytes(
        json.dumps(
            {
                "results": [
                    {
                        "check_id": rule,
                        "path": path,
                        "start": {"line": line},
                        "end": {"line": line},
                        "extra": {
                            "message": "synthetic static candidate",
                            "lines": sources[path].splitlines()[line - 1],
                        },
                    }
                    for path, line, rule in result_rows
                ]
            }
        ).encode(),
        "application/json",
    )
    paths = tuple(sorted(sources))
    ast_summary = collect_python_ast(
        workspace, paths, artifacts, max_source_bytes=32_768
    )
    ast_ref = artifacts.put_json(ast_summary)
    source_ref = artifacts.put_json(
        {"kind": "simple_tracked_sources", "paths": list(paths)}
    )
    coverage_ref = artifacts.put_json(
        {
            "kind": "simple_static_coverage_v1",
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "fingerprint": _SCOPE,
            "expected_count": len(result_rows),
            "verified_count": len(result_rows),
            "gaps": [],
            "unsupported": [],
            "unsupported_files": [],
            "engine_errors": [],
            "ast_parsed_file_count": len(paths),
            "ast_parse_error_count": 0,
            "ast_parse_errors": [],
            "ast_oversize_count": 0,
            "ast_oversize_paths": [],
            "ast_truncated": False,
        }
    )
    bundle_ref = artifacts.put_json(
        {
            "kind": "simple_static_fact_bundle",
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "static_coverage_ref": coverage_ref.model_dump(mode="json"),
            "source_manifest_ref": source_ref.model_dump(mode="json"),
            "engine_raw_refs": [raw_ref.model_dump(mode="json")],
            "engine_raw_sources": [
                {
                    "ref": raw_ref.model_dump(mode="json"),
                    "engine": "opengrep",
                    "verified_pairs": [
                        {"path": path, "rule_id": rule}
                        for path, _line, rule in result_rows
                    ],
                }
            ],
            "tool_result_refs": [
                ast_ref.model_dump(mode="json"),
                raw_ref.model_dump(mode="json"),
            ],
            "ast_summary": ast_summary,
        }
    )
    static = _StaticBootstrap(
        StaticBootstrapResult(
            repository_profile_ref=artifacts.put_json({"kind": "fixture-profile"}),
            static_bundle_ref=bundle_ref,
            static_coverage_ref=coverage_ref,
            workspace_path=workspace,
            static_disposition="FULL",
        )
    )
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    discovery = _DiscoveryClient()
    events: list[str] = []
    proposer = _FixtureProposer(
        data_dir,
        events,
        omit_storage_once=omit_storage_once,
        incomplete_storage_review=incomplete_storage_review,
    )
    ids = iter((identity.analysis_id, identity.workspace_id))
    application = SimpleAnalysisApplication(
        data_dir=data_dir,
        store=store,
        static_bootstrap=static,
        hypothesis_bootstrap=proposer,
        runner_factory=lambda backing, root, _static: _FixtureRunner(
            backing, data_dir, root, events
        ),
        id_factory=lambda: next(ids),
        candidate_pipeline_enabled=True,
        candidate_pipeline_version=pipeline_version,
        candidate_client_factory=lambda *_: discovery,
    )
    return application, store, discovery, proposer, events, data_dir


def _request(data_dir: Path) -> SimpleAnalysisRequest:
    workspace = data_dir / "checkout"
    commit = (
        subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=workspace)
        .decode("ascii")
        .strip()
        if (workspace / ".git").is_dir()
        else _COMMIT
    )
    return SimpleAnalysisRequest(
        data_dir=data_dir,
        repository="https://github.com/example/fixture",
        commit=commit,
    )


class _HandoffClient:
    def __init__(
        self,
        *,
        poc_validated: bool,
        gates_accepted: bool,
        fail_agent_once: str | None = None,
        report_local_url: bool = False,
    ) -> None:
        self.poc_validated = poc_validated
        self.gates_accepted = gates_accepted
        self.fail_agent_once = fail_agent_once
        self.report_local_url = report_local_url
        self.calls: Counter[str] = Counter()
        self.prompts: dict[str, list[bytes]] = {}

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
    ) -> SimpleLLMCallResult | StageFailure:
        del output_schema, timeout_ms, owner, prompt_bytes, invocation_id
        self.calls[agent_name] += 1
        self.prompts.setdefault(agent_name, []).append(prompt)
        if self.fail_agent_once == agent_name:
            self.fail_agent_once = None
            return StageFailure(
                code="INVALID_OUTPUT",
                retryable=True,
                safe_message="Fixture provider returned invalid structured output",
            )
        observation = "REPRODUCED" if self.poc_validated else "NOT_REPRODUCED"
        values: dict[str, dict[str, object]] = {
            "pro_evidence": {
                "claims": ["A route parameter reaches subprocess.run."],
                "evidence_refs": [],
                "limitations": [],
                "requested_paths": [],
            },
            "con_evidence": {
                "claims": [],
                "evidence_refs": [],
                "limitations": ["Fixture evidence only"],
                "requested_paths": [],
            },
            "initial_verification": {
                "initial_assessment": "HOLD",
                "rationale": "Run the isolated PoC.",
                "reproduction_goal": "Observe the exact fixture marker.",
                "environment_requirements": ["python:3.12"],
                "unmet_external_prerequisites": [],
                "supporting_refs": [],
                "limitations": [],
            },
            "poc_candidate": {
                "content": "#!/bin/sh\nset -eu\nprintf 'REPRODUCED\\n'\n",
            },
            "poc_interpretation": {
                "outcome": "SUPPORTED" if self.poc_validated else "DISPROVED",
                "rationale": f"The isolated fixture returned {observation}.",
                "limitations": [],
            },
            "verification_result": {
                "verdict": "TRUE" if self.poc_validated else "FALSE",
                "rationale": "The exact local execution is decisive for this fixture.",
                "supporting_refs": [],
                "limitations": [],
                "unresolved_conditions": [],
                "required_capabilities": [],
                "provided_capabilities": [],
                "entities": [],
            },
            "cwe_label": {
                "primary_cwe": "CWE-78",
                "alternatives": [],
                "rationale": "Fixture command execution path.",
                "supporting_refs": [],
            },
            "technical_gate": {
                "status": "ACCEPT",
                "rationale": "Same-attempt fixture evidence.",
                "checks": ["Validated PoC and final TRUE agree."],
                "revision_requests": [],
            },
            "report_draft": {
                "schema_version": 2,
                "en": {
                    "title": "Fixture command injection",
                    "summary": "A local fixture reproduces the tested path.",
                    "details": "The isolated test reached the command sink.",
                    "impact": "Command execution in the fixture environment.",
                    "recommendation": "Constrain untrusted command arguments.",
                    "limitations": [
                        "Synthetic fixture only; not a real vulnerability."
                    ],
                    "review_items": [
                        "Verify against the actual target before reporting."
                    ],
                },
                "ko": {
                    "title": "시험용 명령어 삽입",
                    "summary": "격리된 시험 환경에서만 경로를 재현했습니다.",
                    "details": "시험 입력이 명령 실행 경로에 도달했습니다.",
                    "impact": "시험 환경에서 명령 실행이 가능합니다.",
                    "recommendation": "신뢰할 수 없는 명령 인자를 제한하세요.",
                    "limitations": ["합성 fixture이며 실제 취약점이 아닙니다."],
                    "review_items": ["실제 대상은 별도로 확인해야 합니다."],
                },
                "citations": [],
            },
        }
        if agent_name == "report_draft" and self.report_local_url:
            korean = cast(dict[str, Any], values[agent_name]["ko"])
            korean["details"] = (
                "시험 입력은 file:relative/private folder/source, 다음 단계로 갔습니다."
            )
        if agent_name == "rule_scope_gate":
            status = "PASS" if self.gates_accepted else "FAIL"
            lines = (
                "Security reports from any researcher are accepted.",
                (
                    "Repository fixture version 2.x is in scope."
                    if self.gates_accepted
                    else "Repository fixture version 2.x is out of scope."
                ),
                "High-impact security vulnerabilities are eligible.",
                "Local proof-of-concept testing is permitted.",
                "Private reports are permitted.",
            )
            values[agent_name] = {
                "rationale": "Synthetic policy fixture only.",
                "restrictions": [],
                "testing_restriction_compliance": "PASS",
                "testing_poc_quote": "printf 'REPRODUCED\\n'",
                "axes": {
                    name: {
                        "status": status if name == "asset_scope" else "PASS",
                        "line": index + 2,
                        "quote": line,
                        "reason": "Exact fixture policy line.",
                    }
                    for index, (name, line) in enumerate(
                        zip(
                            ("rules", "asset_scope", "impact", "testing", "reporting"),
                            lines,
                            strict=True,
                        )
                    )
                },
            }
        assert agent_name in values, agent_name
        return SimpleLLMCallResult(
            value=cast(dict[str, JsonValue], values[agent_name]),
            prompt_digest="a" * 64,
            output_digest=hashlib.sha256(
                canonical_bytes(values[agent_name])
            ).hexdigest(),
        )


class _HandoffEnvironment:
    def __init__(self, data_dir: Path, *, degraded: bool) -> None:
        self.data_dir = data_dir
        self.degraded = degraded

    async def prepare(
        self,
        checkpoint: StageCheckpoint,
        prior: Mapping[SimpleStage, StageCheckpoint],
        requirements: tuple[str, ...],
    ) -> ReproductionEnvironment:
        del prior
        assert requirements == ("python:3.12",)
        image_digest = "sha256:" + "1" * 64
        recipe_ref = SimpleArtifactRepository(
            self.data_dir, checkpoint.identity
        ).put_json(
            {
                "kind": "simple_environment_recipe",
                "status": "BUILT",
                "analysis_id": checkpoint.identity.analysis_id,
                "workspace_id": checkpoint.identity.workspace_id,
                "commit_id": checkpoint.identity.commit_id,
                "hypothesis_id": checkpoint.identity.hypothesis_id,
                "attempt_id": checkpoint.attempt_id,
                "dockerfile_source": "GENERATED",
                "degraded": self.degraded,
                "image_digest": image_digest,
            }
        )
        return ReproductionEnvironment(recipe_ref, image_digest)


class _HandoffDocker:
    def __init__(self, *, poc_validated: bool) -> None:
        self.poc_validated = poc_validated
        self.calls = 0

    async def materialize_poc(self, *_args: Any) -> str:
        return "/tmp/sastsimi-poc-candidate"

    async def execute(self, *_args: Any, **_kwargs: Any) -> DockerCommandOutcome:
        self.calls += 1
        return DockerCommandOutcome(
            exit_code=0 if self.poc_validated else 1,
            stdout=b"REPRODUCED\n" if self.poc_validated else b"NOT_REPRODUCED\n",
            stderr=b"",
            timed_out=False,
        )


class _HandoffContainers:
    async def acquire(self, _checkpoint: StageCheckpoint) -> str:
        return "a" * 64

    async def release(self, _checkpoint: StageCheckpoint, _container_id: str) -> bool:
        return True


def build_handoff_harness(
    tmp_path: Path,
    *,
    poc_validated: bool,
    gates_accepted: bool,
    interrupt_once: bool = False,
    old_nonretryable_poc: bool = False,
    fail_agent_once: str | None = None,
    report_local_url: bool = False,
) -> tuple[SimpleAnalysisApplication, CheckpointIdentity]:
    app, store, _discovery, _proposer, _events, data_dir = _fixture(
        tmp_path, omit_storage_once=interrupt_once, committed_checkout=True
    )
    commit = (
        subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=data_dir / "checkout")
        .decode("ascii")
        .strip()
    )
    identity = CheckpointIdentity(
        analysis_id="analysis-fixture",
        workspace_id="workspace-fixture",
        commit_id=commit,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(data_dir, identity)
    policy_lines = (
        "# Security policy",
        "Security reports from any researcher are accepted.",
        (
            "Repository fixture version 2.x is in scope."
            if gates_accepted
            else "Repository fixture version 2.x is out of scope."
        ),
        "High-impact security vulnerabilities are eligible.",
        "Local proof-of-concept testing is permitted.",
        "Private reports are permitted.",
    )
    body = "\n".join(policy_lines).encode()
    body_ref = artifacts.put_bytes(body, "text/markdown")
    blob_sha = hashlib.sha1(
        b"blob " + str(len(body)).encode() + b"\0" + body
    ).hexdigest()
    snapshot_ref = artifacts.put_json(
        {
            "kind": "simple_policy_snapshot",
            "version": 1,
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "target_repository": "https://github.com/example/fixture",
            "status": "FOUND",
            "reason_code": "POLICY_FOUND",
            "source_kind": "github_contents_api",
            "owner": "example",
            "repo": "fixture",
            "publisher": "example/fixture",
            "source_url": "https://api.github.com/repos/example/fixture/contents/SECURITY.md?ref=main",
            "source_path": "SECURITY.md",
            "blob_sha": blob_sha,
            "etag": '"fixture"',
            "content_type": "text/markdown",
            "checked_at": datetime.now(UTC),
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "body_ref": body_ref.model_dump(mode="json"),
        }
    )
    static = cast(_StaticBootstrap, app._static)
    static.result = static.result.model_copy(
        update={"policy_snapshot_ref": snapshot_ref}
    )
    client = _HandoffClient(
        poc_validated=poc_validated,
        gates_accepted=gates_accepted,
        fail_agent_once=fail_agent_once,
        report_local_url=report_local_url,
    )
    docker = _HandoffDocker(poc_validated=poc_validated)
    containers = _HandoffContainers()
    environments = _HandoffEnvironment(data_dir, degraded=old_nonretryable_poc)

    def runner_factory(
        backing: SimpleCheckpointStore,
        child: CheckpointIdentity,
        source: StaticBootstrapResult,
    ) -> SimpleRuntimeRunner:
        child_artifacts = SimpleArtifactRepository(data_dir, child)
        handlers = build_stage_handlers(
            client=client,
            artifacts=child_artifacts,
            docker=docker,  # type: ignore[arg-type]
            containers=containers,
            environments=environments,
            store=backing,
            policy_snapshot_ref=snapshot_ref,
            repository_url="https://github.com/example/fixture",
            workspace_path=source.workspace_path,
            static_bundle_ref=source.static_bundle_ref,
        )
        return SimpleRuntimeRunner(
            backing,
            handlers,
            policy_snapshot_ref=snapshot_ref,
            codex_invalid_output_resume=True,
        )

    app._runner_factory = runner_factory
    app.fixture_agent_calls = client.calls  # type: ignore[attr-defined]
    app.fixture_agent_prompts = client.prompts  # type: ignore[attr-defined]
    app.fixture_docker = docker  # type: ignore[attr-defined]
    return app, identity


def _reopen_handoff_app(
    app: SimpleAnalysisApplication,
    data_dir: Path,
) -> SimpleAnalysisApplication:
    return SimpleAnalysisApplication(
        data_dir=data_dir,
        store=SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3"),
        static_bootstrap=app._static,
        hypothesis_bootstrap=app._hypotheses,
        runner_factory=app._runner_factory,
        candidate_pipeline_enabled=True,
        candidate_pipeline_version=2,
        candidate_client_factory=app._candidate_client_factory,
        candidate_hypothesis_bootstrap=app._candidate_hypotheses,
    )


@pytest.mark.asyncio
async def test_streaming_fixture_preserves_known_positive_and_exact_public_counts(
    tmp_path: Path,
) -> None:
    app, store, discovery, proposer, events, data_dir = _fixture(tmp_path)

    outcome = await app.analyze(_request(data_dir))

    # If the producer regains its all-batches barrier, this ordering breaks.
    assert outcome.status == "COMPLETE", outcome.error_code
    assert events.index("batch:api.py") < events.index("pro_con:known-command-path")
    assert events.index("pro_con:known-command-path") < events.index("batch:storage.py")
    assert events.index("pro_con:known-command-path") < next(
        index for index, event in enumerate(events) if event.startswith("surface:")
    )
    assert proposer.batch_calls and len(proposer.batch_calls) == 2
    assert discovery.calls == 1
    assert discovery.prompt_bytes > 0 and proposer.shared_context_bytes > 0

    candidates = store.list_candidates(outcome.identity, _SCOPE, limit=10)
    selected_ids = {
        item.candidate_id
        for item in candidates
        if item.decision in {"INCLUDE", "UNDECIDED"}
    }
    terminal_ids = set(store.list_candidate_batch_outcomes(outcome.identity, _SCOPE))
    run = store.require_analysis_run(outcome.identity.analysis_id)
    assert selected_ids == terminal_ids
    assert len(selected_ids) == 2
    assert store.list_hypotheses(outcome.identity) == ("known-command-path",)
    assert run.candidate_terminal is not None
    assert run.candidate_terminal.producer_finished is True
    assert run.candidate_terminal.pending_child_count == 0
    assert run.candidate_terminal.decision_counts["INCLUDE"] == 2
    assert run.candidate_terminal.decision_counts["EXCLUDE"] == 1
    assert run.candidate_terminal.hypothesis_count == 1
    assert run.candidate_terminal.surface_counts == {
        "COVERED": 4,
        "UNCOVERED": 0,
        "INSUFFICIENT": 0,
    }
    assert len(proposer.surface_calls) == 4

    public = _public_app(data_dir)
    status = public.status(outcome.display_analysis_id)
    assert status["status"] == "COMPLETE"
    assert status["percentage_kind"] == "known_checkpoint_fraction"
    assert status["candidate_total_count"] == 3
    assert status["hypothesis_count"] == 1
    assert status["finding_count"] == 0
    assert status["phase_counts"] == {
        "static": {"completed": 1, "known": 1},
        "triage": {"completed": 3, "known": 3},
        "candidate_deep": {"completed": 2, "known": 2},
        "verification": {"completed": 1, "known": 1},
        "poc": {"attempted": 0, "completed": 0},
        "surface": {
            "recorded_contexts": 4,
            "recorded_surfaces": 4,
            "completed": 4,
            "total": 4,
            "covered": 4,
            "uncovered": 0,
            "insufficient": 0,
        },
    }
    output = StringIO()
    emit_public("text", output, command="status", data=status)
    rendered = output.getvalue()
    assert "후보: 총 3개" in rendered
    assert "포함 2" in rendered and "제외 1" in rendered
    assert "심층 분석: 진행 0 · 완료 2 · 대기 0" in rendered
    assert "가설: 1개" in rendered and "Finding: 0개" in rendered
    assert "보안 surface: 검토 근거 충족 4/4 · 미검토 0 · 근거 부족 0" in rendered


@pytest.mark.asyncio
async def test_streaming_fixture_keeps_single_file_ids_across_db_page(
    tmp_path: Path,
) -> None:
    app, store, _discovery, proposer, _events, data_dir = _fixture(
        tmp_path, bulk_candidate_count=33
    )

    outcome = await app.analyze(_request(data_dir))

    assert outcome.status == "COMPLETE", outcome.error_code
    selected = store.list_candidate_batch_page(outcome.identity, _SCOPE, limit=100)
    first_page = store.list_candidate_batch_page(outcome.identity, _SCOPE, limit=32)
    second_page = store.list_candidate_batch_page(
        outcome.identity,
        _SCOPE,
        after=(first_page[-1].path, first_page[-1].candidate_id),
        limit=32,
    )
    assert len(first_page) == 32
    assert len(second_page) == 3
    assert first_page[-1].path == second_page[0].path == "bulk.py"
    bulk_ids = {item.candidate_id for item in selected if item.path == "bulk.py"}
    assert len(bulk_ids) == 33
    submitted_bulk_ids = tuple(
        candidate_id
        for path, ids in proposer.batch_calls
        if path == "bulk.py"
        for candidate_id in ids
    )
    assert len(submitted_bulk_ids) == len(set(submitted_bulk_ids)) == 33
    assert set(submitted_bulk_ids) == bulk_ids
    assert set(store.list_candidate_batch_outcomes(outcome.identity, _SCOPE)) == {
        item.candidate_id for item in selected
    }


@pytest.mark.asyncio
async def test_streaming_fixture_resume_conserves_completed_child_and_counts(
    tmp_path: Path,
) -> None:
    app, store, _discovery, proposer, events, data_dir = _fixture(
        tmp_path, omit_storage_once=True
    )
    first = await app.analyze(_request(data_dir))
    assert first.status == "BLOCKED"
    assert first.error_code == "HYPOTHESIS_BATCH_OUTPUT_INVALID"
    assert events.count("pro_con:known-command-path") == 1
    assert len(store.list_candidate_batch_outcomes(first.identity, _SCOPE)) == 1

    second = await app.resume(first.identity.analysis_id)

    assert second.status == "COMPLETE", second.error_code
    assert Counter(path for path, _ids in proposer.batch_calls) == {
        "api.py": 1,
        "storage.py": 2,
    }
    assert events.count("pro_con:known-command-path") == 1
    assert store.list_hypotheses(second.identity) == ("known-command-path",)
    assert len(store.list_candidate_batch_outcomes(second.identity, _SCOPE)) == 2
    assert (
        store.require_analysis_run(second.identity.analysis_id).candidate_terminal
        is not None
    )
    before_status = _public_app(data_dir).status(second.display_analysis_id)
    third = await app.resume(first.identity.analysis_id)
    after_status = _public_app(data_dir).status(third.display_analysis_id)
    assert third.status == "COMPLETE"
    assert after_status["phase_counts"] == before_status["phase_counts"]
    assert after_status["candidate_total_count"] == 3
    assert after_status["hypothesis_count"] == 1
    assert events.count("pro_con:known-command-path") == 1


@pytest.mark.asyncio
async def test_streaming_fixture_unreviewed_sink_is_partial_in_terminal_and_cli(
    tmp_path: Path,
) -> None:
    app, store, _discovery, proposer, _events, data_dir = _fixture(
        tmp_path, incomplete_storage_review=True
    )

    outcome = await app.analyze(_request(data_dir))

    assert outcome.status == "PARTIAL", outcome.error_code
    assert "storage.py:2" in {location for _id, location in proposer.surface_calls}
    terminal = store.require_analysis_run(
        outcome.identity.analysis_id
    ).candidate_terminal
    assert terminal is not None
    assert terminal.surface_counts == {
        "COVERED": 3,
        "UNCOVERED": 0,
        "INSUFFICIENT": 1,
    }
    status = _public_app(data_dir).status(outcome.display_analysis_id)
    assert status["status"] == "PARTIAL"
    phase_counts = cast(dict[str, dict[str, int]], status["phase_counts"])
    assert phase_counts["surface"] == {
        "recorded_contexts": 4,
        "recorded_surfaces": 4,
        "completed": 3,
        "total": 4,
        "covered": 3,
        "uncovered": 0,
        "insufficient": 1,
    }
    output = StringIO()
    emit_public("text", output, command="status", data=status)
    assert (
        "보안 surface: 검토 근거 충족 3/4 · 미검토 0 · 근거 부족 1" in output.getvalue()
    )


@pytest.mark.asyncio
async def test_synthetic_v1_v2_benchmark_records_actual_fake_transport_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    measured: dict[str, dict[str, int | float | bool]] = {}
    for version in (1, 2):
        app, store, discovery, _manual, events, data_dir = _fixture(
            tmp_path / f"v{version}", pipeline_version=version
        )
        transport = _MeasuredHypothesisTransport(events)
        bootstrap = DirectHypothesisBootstrap(
            data_dir=data_dir,
            client_factory=lambda *_, selected=transport: selected,
            store=store,
        )
        app._candidate_hypotheses = bootstrap
        app._hypotheses = bootstrap
        child_started_ns: list[int] = []

        def fixture_runner_factory(
            backing: SimpleCheckpointStore,
            root: CheckpointIdentity,
            _static: StaticBootstrapResult,
            *,
            fixture_data_dir: Path = data_dir,
            fixture_events: list[str] = events,
            started_times: list[int] = child_started_ns,
        ) -> _FixtureRunner:
            return _FixtureRunner(
                backing, fixture_data_dir, root, fixture_events, started_times
            )

        app._runner_factory = fixture_runner_factory
        peak_pending = 0
        original_list_incomplete = store.list_incomplete_hypotheses

        def observed_incomplete(
            identity: CheckpointIdentity,
            *,
            after_id: str | None = None,
            limit: int = 100,
            original: Callable[..., tuple[str, ...]] = original_list_incomplete,
        ) -> tuple[str, ...]:
            nonlocal peak_pending
            pending = original(identity, limit=100)
            peak_pending = max(peak_pending, len(pending))
            return original(identity, after_id=after_id, limit=limit)

        monkeypatch.setattr(store, "list_incomplete_hypotheses", observed_incomplete)
        started_ns = perf_counter_ns()
        outcome = await app.analyze(_request(data_dir))
        assert outcome.status == "COMPLETE", (version, outcome.error_code)
        assert len(child_started_ns) == 1
        positive = next(
            candidate
            for candidate in store.list_candidates(outcome.identity, _SCOPE, limit=10)
            if candidate.path == "api.py" and candidate.line == 3
        )
        retained = bool(
            store.list_candidate_hypothesis_ids(
                outcome.identity, _SCOPE, positive.candidate_id
            )
        )
        measured[f"v{version}"] = {
            "llm_calls": discovery.calls + len(transport.requests),
            "serialized_prompt_bytes": discovery.prompt_bytes
            + sum(len(prompt) for _agent, prompt in transport.requests),
            "first_child_latency_ms": round(
                (child_started_ns[0] - started_ns) / 1_000_000, 3
            ),
            "pending_peak": peak_pending,
            "known_positive_retained": retained,
        }
        if version == 1:
            assert events.index("legacy_source_page") < next(
                index
                for index, event in enumerate(events)
                if event.startswith("pro_con:")
            )
        else:
            assert next(
                index
                for index, event in enumerate(events)
                if event.startswith("pro_con:")
            ) < events.index("hypothesis_batch:storage.py")

    assert measured["v1"]["known_positive_retained"] is True
    assert measured["v2"]["known_positive_retained"] is True
    assert measured["v1"]["llm_calls"] == 4
    assert measured["v2"]["llm_calls"] == 7
    assert measured["v1"]["pending_peak"] == 1
    assert measured["v2"]["pending_peak"] == 1
    assert measured["v1"]["serialized_prompt_bytes"] > 0
    assert measured["v2"]["serialized_prompt_bytes"] > 0
    print("fixture_v1_v2_benchmark=" + json.dumps(measured, sort_keys=True))


@pytest.mark.asyncio
async def test_cloned_legacy_run_reuses_v1_page_and_child_checkpoints(
    tmp_path: Path,
) -> None:
    app, store, _discovery, _manual, events, data_dir = _fixture(
        tmp_path / "original", pipeline_version=1
    )
    first_transport = _MeasuredHypothesisTransport(events)
    first_bootstrap = DirectHypothesisBootstrap(
        data_dir=data_dir,
        client_factory=lambda *_: first_transport,
        store=store,
    )
    app._candidate_hypotheses = first_bootstrap
    app._hypotheses = first_bootstrap
    first = await app.analyze(_request(data_dir))
    assert first.status == "COMPLETE", first.error_code
    run = store.require_analysis_run(first.identity.analysis_id)
    assert run.candidate_pipeline_version == 1
    assert run.static_bundle_ref is not None
    old_progress = store.survey_progress(
        first.identity.analysis_id, run.static_bundle_ref.content_hash
    )
    assert "__candidate_free_done__" in old_progress
    old_hypothesis_ids = store.list_hypotheses(first.identity)
    assert len(old_hypothesis_ids) == 1

    cloned_data_dir = tmp_path / "cloned" / "data"
    copytree(data_dir, cloned_data_dir)
    cloned_store = SimpleCheckpointStore(cloned_data_dir / "db" / "sastsimi.sqlite3")
    cloned_transport = _MeasuredHypothesisTransport([])
    cloned_bootstrap = DirectHypothesisBootstrap(
        data_dir=cloned_data_dir,
        client_factory=lambda *_: cloned_transport,
        store=cloned_store,
    )
    cloned_static = cast(_StaticBootstrap, app._static).result.model_copy(
        update={"workspace_path": cloned_data_dir / "checkout"}
    )
    cloned_app = SimpleAnalysisApplication(
        data_dir=cloned_data_dir,
        store=cloned_store,
        static_bootstrap=_StaticBootstrap(cloned_static),
        hypothesis_bootstrap=cloned_bootstrap,
        runner_factory=lambda backing, root, _static: _FixtureRunner(
            backing, cloned_data_dir, root, []
        ),
        candidate_pipeline_enabled=True,
        candidate_pipeline_version=2,
        candidate_client_factory=lambda *_: _DiscoveryClient(),
    )

    resumed = await cloned_app.resume(first.identity.analysis_id)

    assert resumed.status == "COMPLETE", resumed.error_code
    assert (
        cloned_store.require_analysis_run(
            resumed.identity.analysis_id
        ).candidate_pipeline_version
        == 1
    )
    assert (
        cloned_store.survey_progress(
            resumed.identity.analysis_id, run.static_bundle_ref.content_hash
        )
        == old_progress
    )
    assert cloned_store.list_hypotheses(resumed.identity) == old_hypothesis_ids
    assert cloned_transport.requests == []


@pytest.mark.asyncio
async def test_handoff_fixture_anchors_proposal_to_committed_source(
    tmp_path: Path,
) -> None:
    app, identity = build_handoff_harness(
        tmp_path, poc_validated=True, gates_accepted=True
    )
    workspace = tmp_path / "data" / "checkout"
    pinned = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=workspace,
        capture_output=True,
        check=False,
    )
    assert pinned.returncode == 0
    assert pinned.stdout.decode("ascii").strip() == identity.commit_id

    outcome = await app.analyze(_request(tmp_path / "data"))
    assert outcome.status == "COMPLETE", (outcome.current_stage, outcome.error_code)
    store = SimpleCheckpointStore(tmp_path / "data" / "db" / "sastsimi.sqlite3")
    child = identity.model_copy(update={"hypothesis_id": "known-command-path"})
    inputs = store.require(child, SimpleStage.PRO_CON_DONE).input_refs
    proposal = json.loads(
        SimpleArtifactRepository(tmp_path / "data", child).read_prompt_proposal(
            inputs[0]
        )
    )
    assert StoredDataRef.model_validate(proposal["shared_context_ref"]) == inputs[1]


@pytest.mark.asyncio
async def test_completed_candidate_rechecks_final_v2_without_replaying_poc(
    tmp_path: Path,
) -> None:
    app, identity = build_handoff_harness(
        tmp_path, poc_validated=True, gates_accepted=True
    )
    data_dir = tmp_path / "data"
    first = await app.analyze(_request(data_dir))
    assert first.status == "COMPLETE", (first.current_stage, first.error_code)
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    child = identity.model_copy(update={"hypothesis_id": "known-command-path"})
    pro_con = store.require(child, SimpleStage.PRO_CON_DONE)
    poc = store.require(child, SimpleStage.POC_EXECUTION_DONE)
    report = store.require(child, SimpleStage.REPORT_DONE)
    final = store.require(child, SimpleStage.VERIFICATION_FINAL_DONE)
    assert final.stage_version == STAGE_VERSION[SimpleStage.VERIFICATION_FINAL_DONE]
    store.save_checkpoint(final.model_copy(update={"stage_version": "2"}))
    assert store.require(child, SimpleStage.REPORT_DONE) == report
    before_calls = dict(app.fixture_agent_calls)  # type: ignore[attr-defined]
    before_docker = app.fixture_docker.calls  # type: ignore[attr-defined]

    second = await _reopen_handoff_app(app, data_dir).resume(identity.analysis_id)

    assert second.status == "COMPLETE", (second.current_stage, second.error_code)
    updated = store.require(child, SimpleStage.VERIFICATION_FINAL_DONE)
    assert updated.stage_version == STAGE_VERSION[SimpleStage.VERIFICATION_FINAL_DONE]
    after_calls = dict(app.fixture_agent_calls)  # type: ignore[attr-defined]
    assert after_calls["verification_result"] == before_calls["verification_result"] + 1
    assert after_calls["pro_evidence"] == before_calls["pro_evidence"]
    assert after_calls["con_evidence"] == before_calls["con_evidence"]
    assert store.require(child, SimpleStage.PRO_CON_DONE) == pro_con
    assert store.require(child, SimpleStage.POC_EXECUTION_DONE) == poc
    assert app.fixture_docker.calls == before_docker  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_validated_fixture_exports_exact_bilingual_bundle(tmp_path: Path) -> None:
    app, identity = build_handoff_harness(
        tmp_path, poc_validated=True, gates_accepted=True
    )
    outcome = await app.analyze(_request(tmp_path / "data"))
    assert outcome.status == "COMPLETE", (outcome.current_stage, outcome.error_code)
    store = SimpleCheckpointStore(tmp_path / "data" / "db" / "sastsimi.sqlite3")
    child = identity.model_copy(update={"hypothesis_id": "known-command-path"})
    checkpoints = {stage: store.require(child, stage) for stage in HYPOTHESIS_STAGES}
    assert checkpoints[SimpleStage.VERIFICATION_FINAL_DONE].verdict == "TRUE"
    assert checkpoints[SimpleStage.TECH_GATE_DONE].gate_decision == "ACCEPT"
    artifacts = SimpleArtifactRepository(tmp_path / "data", child)
    candidate = checkpoints[SimpleStage.POC_CANDIDATE_DONE]
    execution = checkpoints[SimpleStage.POC_EXECUTION_DONE]
    assert candidate.attempt_id == execution.attempt_id
    assert execution.validated_poc_ref is not None
    candidate_data = json.loads(artifacts.read(candidate.output_refs[0]))
    execution_data = json.loads(artifacts.read(execution.output_refs[0]))
    validated_data = json.loads(artifacts.read(execution.validated_poc_ref))
    assert candidate_data["content_ref"] == candidate.output_refs[1].model_dump(
        mode="json"
    )
    assert execution_data["candidate_ref"] == candidate.output_refs[0].model_dump(
        mode="json"
    )
    assert execution_data["content_ref"] == candidate.output_refs[1].model_dump(
        mode="json"
    )
    assert validated_data["execution_ref"] == execution.output_refs[0].model_dump(
        mode="json"
    )
    assert validated_data["attempt_id"] == execution.attempt_id
    prompts = app.fixture_agent_prompts  # type: ignore[attr-defined]
    assert (
        candidate.output_refs[0].content_hash.encode()
        in prompts["poc_interpretation"][0]
    )
    assert (
        execution.output_refs[0].content_hash.encode()
        in prompts["verification_result"][0]
    )
    assert (
        execution.validated_poc_ref.content_hash.encode()
        in prompts["technical_gate"][0]
    )
    assert (
        execution.validated_poc_ref.content_hash.encode()
        in prompts["rule_scope_gate"][0]
    )
    finding_ref = checkpoints[SimpleStage.FINDING_DONE].output_refs[0]
    finding = json.loads(artifacts.read(finding_ref))
    assert finding["status"] == "CONFIRMED"
    assert finding_ref.content_hash.encode() in prompts["report_draft"][0]
    review = project_scope_review(
        checkpoints[SimpleStage.SCOPE_GATE_DONE],
        artifacts,
        policy_snapshot_ref=cast(
            _StaticBootstrap, app._static
        ).result.policy_snapshot_ref,
        repository_url="https://github.com/example/fixture",
    )
    assert review["status"] == "ALLOW"
    manifest, _archive = artifacts.verified_report_bundle(
        checkpoints=checkpoints,
        finding_ref=finding_ref,
        display_id="F-001",
        scope_status=str(review["status"]),
        public_projection=lambda body: safe_public_report(body, review),
    )
    assert {item.path for item in manifest.files} == {
        "report_en.md",
        "report_kr.md",
        "poc.sh",
        "evidence/provenance.json",
        "evidence/stdout.txt",
        "evidence/stderr.txt",
    }
    bundle_path = Path(
        checkpoints[SimpleStage.REPORT_DONE].markdown_path or ""
    ).with_suffix("")
    assert (bundle_path / "bundle.zip").is_file()
    assert b"Fixture command injection" in (bundle_path / "report_en.md").read_bytes()
    assert "시험용 명령어 삽입" in (bundle_path / "report_kr.md").read_text(
        encoding="utf-8"
    )
    assert (bundle_path / "poc.sh").read_bytes() == artifacts.read(
        candidate.output_refs[1]
    )


@pytest.mark.asyncio
async def test_reporter_redacts_local_file_url_in_legacy_and_bundle_reports(
    tmp_path: Path,
) -> None:
    app, identity = build_handoff_harness(
        tmp_path,
        poc_validated=True,
        gates_accepted=True,
        report_local_url=True,
    )
    outcome = await app.analyze(_request(tmp_path / "data"))
    assert outcome.status == "COMPLETE", outcome.error_code
    child = identity.model_copy(update={"hypothesis_id": "known-command-path"})
    store = SimpleCheckpointStore(tmp_path / "data" / "db" / "sastsimi.sqlite3")
    report = store.require(child, SimpleStage.REPORT_DONE)
    artifacts = SimpleArtifactRepository(tmp_path / "data", child)
    legacy = artifacts.read(report.output_refs[1])
    bundle = Path(report.markdown_path or "").with_suffix("")
    korean = (bundle / "report_kr.md").read_bytes()
    for body in (legacy, Path(report.markdown_path or "").read_bytes(), korean):
        assert b"file:relative/private folder/source" not in body
        assert b"folder/source" not in body
        assert b"[REDACTED:LOCAL_FILE_URL]" in body


@pytest.mark.asyncio
async def test_benign_fixture_finishes_without_finding(tmp_path: Path) -> None:
    app, identity = build_handoff_harness(
        tmp_path, poc_validated=False, gates_accepted=False
    )
    outcome = await app.analyze(_request(tmp_path / "data"))
    assert outcome.status == "COMPLETE", (outcome.current_stage, outcome.error_code)
    store = SimpleCheckpointStore(tmp_path / "data" / "db" / "sastsimi.sqlite3")
    child = identity.model_copy(update={"hypothesis_id": "known-command-path"})
    assert store.get(child, SimpleStage.FINDING_DONE) is None
    assert store.get(child, SimpleStage.REPORT_DONE) is None


@pytest.mark.asyncio
async def test_policy_deny_exports_only_restricted_bundle(tmp_path: Path) -> None:
    app, identity = build_handoff_harness(
        tmp_path, poc_validated=True, gates_accepted=False
    )
    outcome = await app.analyze(_request(tmp_path / "data"))
    assert outcome.status == "COMPLETE", (outcome.current_stage, outcome.error_code)
    store = SimpleCheckpointStore(tmp_path / "data" / "db" / "sastsimi.sqlite3")
    child = identity.model_copy(update={"hypothesis_id": "known-command-path"})
    artifacts = SimpleArtifactRepository(tmp_path / "data", child)
    finding = store.require(child, SimpleStage.FINDING_DONE)
    value = json.loads(artifacts.read(finding.output_refs[0]))
    assert value["status"] == "CONFIRMED_RESTRICTED"
    assert value["private_reporting_policy_passed"] is False
    report = store.require(child, SimpleStage.REPORT_DONE)
    assert report.bundle_manifest_ref is not None
    bundle = Path(report.markdown_path or "").with_suffix("")
    english = (bundle / "report_en.md").read_text(encoding="utf-8")
    assert "Scope Gate: `DENY`" in english
    assert "Report permission: `DENY`" in english
    checkpoints = {stage: store.require(child, stage) for stage in HYPOTHESIS_STAGES}
    review = project_scope_review(
        checkpoints[SimpleStage.SCOPE_GATE_DONE],
        artifacts,
        policy_snapshot_ref=cast(
            _StaticBootstrap, app._static
        ).result.policy_snapshot_ref,
        repository_url="https://github.com/example/fixture",
    )
    assert review["status"] == "DENY"
    artifacts.verified_report_bundle(
        checkpoints=checkpoints,
        finding_ref=finding.output_refs[0],
        display_id="F-001",
        scope_status="DENY",
        public_projection=lambda body: safe_public_report(body, review),
    )


@pytest.mark.asyncio
async def test_interrupted_resume_skips_completed_agents(tmp_path: Path) -> None:
    app, identity = build_handoff_harness(
        tmp_path,
        poc_validated=True,
        gates_accepted=True,
        interrupt_once=True,
    )
    first = await app.analyze(_request(tmp_path / "data"))
    assert first.status == "BLOCKED"
    before_calls = dict(app.fixture_agent_calls)  # type: ignore[attr-defined]
    reopened = _reopen_handoff_app(app, tmp_path / "data")
    second = await reopened.resume(identity.analysis_id)
    assert second.status == "COMPLETE", second.error_code
    after_calls = dict(app.fixture_agent_calls)  # type: ignore[attr-defined]
    assert after_calls == before_calls
    assert after_calls["pro_evidence"] == 1
    assert after_calls["con_evidence"] == 1
    assert after_calls["initial_verification"] == 1
    assert after_calls["report_draft"] == 1


@pytest.mark.asyncio
async def test_agent_failure_resume_reuses_validated_poc(tmp_path: Path) -> None:
    app, identity = build_handoff_harness(
        tmp_path,
        poc_validated=True,
        gates_accepted=True,
        fail_agent_once="report_draft",
    )
    first = await app.analyze(_request(tmp_path / "data"))
    assert first.status == "BLOCKED"
    assert first.error_code == "INVALID_OUTPUT"
    before_calls = dict(app.fixture_agent_calls)  # type: ignore[attr-defined]
    assert before_calls["report_draft"] == 1
    assert app.fixture_docker.calls == 1  # type: ignore[attr-defined]

    reopened = _reopen_handoff_app(app, tmp_path / "data")
    second = await reopened.resume(identity.analysis_id)

    assert second.status == "COMPLETE", second.error_code
    after_calls = dict(app.fixture_agent_calls)  # type: ignore[attr-defined]
    assert after_calls == before_calls | {"report_draft": 2}
    assert app.fixture_docker.calls == 1  # type: ignore[attr-defined]
    store = SimpleCheckpointStore(tmp_path / "data" / "db" / "sastsimi.sqlite3")
    child = identity.model_copy(update={"hypothesis_id": "known-command-path"})
    assert store.require(child, SimpleStage.REPORT_DONE).status is StageStatus.SUCCEEDED


@pytest.mark.asyncio
async def test_old_flask_nonretryable_checkpoint_is_not_reopened(
    tmp_path: Path,
) -> None:
    app, identity = build_handoff_harness(
        tmp_path,
        poc_validated=True,
        gates_accepted=True,
        old_nonretryable_poc=True,
    )
    first = await app.analyze(_request(tmp_path / "data"))
    assert first.status == "BLOCKED"
    assert first.error_code == "POC_ENVIRONMENT_UNVERIFIED"
    store = SimpleCheckpointStore(tmp_path / "data" / "db" / "sastsimi.sqlite3")
    child = identity.model_copy(update={"hypothesis_id": "known-command-path"})
    blocked = store.require(child, SimpleStage.POC_EXECUTION_DONE)
    # Simulate a pre-existing source-only PoC checkpoint, then reopen the DB.
    assert blocked.retryable is False
    assert blocked.stage_version == STAGE_VERSION[SimpleStage.POC_EXECUTION_DONE]
    before = dict(app.fixture_agent_calls)  # type: ignore[attr-defined]
    second = await _reopen_handoff_app(app, tmp_path / "data").resume(
        identity.analysis_id
    )
    assert second.status == "BLOCKED"
    assert second.error_code == "POC_ENVIRONMENT_UNVERIFIED"
    assert store.require(child, SimpleStage.POC_EXECUTION_DONE) == blocked
    assert dict(app.fixture_agent_calls) == before  # type: ignore[attr-defined]
