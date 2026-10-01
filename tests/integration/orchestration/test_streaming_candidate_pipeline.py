"""Exercise the v2 producer, child queue, surface proof, and public status together.

Only the Discovery/Hypothesis responses and child verification are synthetic.
The source inventory, AST, artifacts, SQLite checkpoints, orchestration,
coverage, progress projection, and CLI rendering are production components.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Callable, Mapping
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
from sastsimi.interfaces.cli.public import emit_public
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
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.simple_runtime.surface_contexts import SurfaceContext

_COMMIT = "a" * 40
_SCOPE = "fixture-python-scope"
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
        return SimpleLLMCallResult(
            value={
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
            },
            prompt_digest="a" * 64,
            output_digest="b" * 64,
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
        pro_ref = artifacts.put_json(
            {"kind": "simple_pro_evidence", "path": "api.py:3"}
        )
        con_ref = artifacts.put_json(
            {"kind": "simple_con_evidence", "path": "api.py:3"}
        )
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
            output_digest="b" * 64,
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
        (workspace / name).write_text(source, encoding="utf-8")
    identity = CheckpointIdentity(
        analysis_id="analysis-fixture",
        workspace_id="workspace-fixture",
        commit_id=_COMMIT,
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
    return SimpleAnalysisRequest(
        data_dir=data_dir,
        repository="https://github.com/example/fixture",
        commit=_COMMIT,
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
