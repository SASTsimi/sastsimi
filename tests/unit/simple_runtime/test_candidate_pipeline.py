from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime.application import (
    HypothesisSeed,
    SimpleAnalysisApplication,
    SimpleAnalysisRequest,
    StaticBootstrapResult,
)
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.ast_facts import collect_python_ast
from sastsimi.simple_runtime.models import (
    STAGE_VERSION,
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageFailure,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.provider import SimpleLLMCallResult
from sastsimi.simple_runtime.runner import RunOutcome, SimpleRuntimeRunner
from sastsimi.simple_runtime.store import SimpleCheckpointStore


class _Static:
    def __init__(self, result: StaticBootstrapResult) -> None:
        self.result = result
        self.calls = 0

    async def run(self, _request: object, _identity: object) -> StaticBootstrapResult:
        self.calls += 1
        return self.result


class _Hypotheses:
    def __init__(self) -> None:
        self.calls = 0

    async def propose(self, _identity: object, _static: object) -> tuple[()]:
        self.calls += 1
        return ()

    async def propose_page(
        self,
        _identity: CheckpointIdentity,
        _static: StaticBootstrapResult,
        *,
        after_cursor: str | None,
    ) -> tuple[tuple[HypothesisSeed, ...], None]:
        assert after_cursor is None
        self.calls += 1
        return (), None


class _PagedHypotheses:
    def __init__(self) -> None:
        self.cursors: list[str | None] = []

    async def propose(
        self, _identity: CheckpointIdentity, _static: StaticBootstrapResult
    ) -> tuple[HypothesisSeed, ...]:
        raise AssertionError("paged exploration must use propose_page")

    async def propose_page(
        self,
        _identity: CheckpointIdentity,
        _static: StaticBootstrapResult,
        *,
        after_cursor: str | None,
        page_budget_bytes: int = 32_768,
    ) -> tuple[tuple[HypothesisSeed, ...], str | None] | StageFailure:
        del page_budget_bytes
        self.cursors.append(after_cursor)
        return (), {None: "page-1", "page-1": "page-2", "page-2": None}[after_cursor]


class _Client:
    def __init__(self, *, budget: bool = False, decision: str = "EXCLUDE") -> None:
        self.budget = budget
        self.decision = decision
        self.calls = 0

    def budget_failure(self) -> StageFailure | None:
        if self.budget:
            return StageFailure(
                code="LLM_TOKEN_BUDGET_EXHAUSTED",
                retryable=False,
                safe_message="budget",
            )
        return None

    async def call(
        self,
        *,
        prompt: bytes,
        output_schema: Mapping[str, Any],
        timeout_ms: int,
        agent_name: str = "agent",
    ) -> SimpleLLMCallResult:
        del output_schema, timeout_ms
        assert agent_name == "discovery"
        self.calls += 1
        rows = json.loads(prompt.split(b"<CANDIDATES>")[1].split(b"</CANDIDATES>")[0])
        return SimpleLLMCallResult(
            value={
                "decisions": [
                    {
                        "candidate_id": row["candidate_id"],
                        "status": self.decision,
                        "reason": "not a vulnerability path",
                        "evidence": "isolated call site",
                    }
                    for row in rows
                ]
            },
            prompt_digest="a" * 64,
            output_digest="b" * 64,
        )


def _setup(
    tmp_path: Path,
    *,
    budget: bool = False,
    result_count: int = 1,
    decision: str = "EXCLUDE",
    partial: bool = False,
    with_ast_summary: bool = False,
    evidence_excerpt: str | None = None,
) -> tuple[SimpleAnalysisApplication, SimpleCheckpointStore, _Client, _Hypotheses]:
    data_dir = tmp_path / "data"
    workspace = tmp_path / "checkout"
    workspace.mkdir()
    (workspace / "app.py").write_text(
        "def route(x):\n" + "    eval(x)\n" * result_count, encoding="utf-8"
    )
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(data_dir, identity)
    raw_ref = artifacts.put_bytes(
        json.dumps(
            {
                "results": [
                    {
                        "check_id": "python.eval",
                        "path": "app.py",
                        "start": {"line": i + 2},
                        "end": {"line": i + 2},
                        "extra": {
                            "message": "eval call",
                            **(
                                {"lines": evidence_excerpt}
                                if evidence_excerpt is not None
                                else {}
                            ),
                        },
                    }
                    for i in range(result_count)
                ]
            }
        ).encode(),
        "application/json",
    )
    ast_summary = (
        collect_python_ast(workspace, ("app.py",), artifacts, max_source_bytes=32_768)
        if with_ast_summary
        else None
    )
    ast_ref = artifacts.put_json(
        ast_summary
        if ast_summary is not None
        else {"kind": "simple_python_ast", "facts": []}
    )
    source_ref = artifacts.put_json(
        {"kind": "simple_tracked_sources", "paths": ["app.py"]}
    )
    coverage_ref = artifacts.put_json(
        {
            "kind": "simple_static_coverage_v1",
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "fingerprint": "scope-1",
            "expected_count": 1,
            "verified_count": 1,
            "gaps": [],
            "unsupported": [],
            **(
                {
                    "ast_parsed_file_count": 1,
                    "ast_parse_error_count": 0,
                    "ast_parse_errors": [],
                    "ast_oversize_count": 0,
                    "ast_oversize_paths": [],
                    "ast_truncated": False,
                }
                if ast_summary is not None
                else {}
            ),
            "out_of_scope_product_files": [
                {"path": "web/app.ts", "reason": "PYTHON_ONLY"}
            ]
            if partial
            else [],
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
                    "verified_pairs": [{"path": "app.py", "rule_id": "python.eval"}],
                }
            ],
            "tool_result_refs": [
                ast_ref.model_dump(mode="json"),
                raw_ref.model_dump(mode="json"),
            ],
            **({"ast_summary": ast_summary} if ast_summary is not None else {}),
        }
    )
    static = _Static(
        StaticBootstrapResult(
            repository_profile_ref=artifacts.put_json({"kind": "profile"}),
            static_bundle_ref=bundle_ref,
            static_coverage_ref=coverage_ref,
            workspace_path=workspace,
            static_disposition="PARTIAL" if partial else "FULL",
        )
    )
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    client = _Client(budget=budget, decision=decision)
    hypotheses = _Hypotheses()
    ids = iter(("analysis-1", "workspace-1"))
    app = SimpleAnalysisApplication(
        data_dir=data_dir,
        store=store,
        static_bootstrap=static,
        hypothesis_bootstrap=hypotheses,
        runner_factory=lambda *_: (_ for _ in ()).throw(AssertionError("runner")),
        id_factory=lambda: next(ids),
        candidate_pipeline_enabled=True,
        candidate_client_factory=lambda *_: client,
    )
    return app, store, client, hypotheses


def _cleanup_audit(
    artifacts: SimpleArtifactRepository,
    checkpoint: StageCheckpoint,
    *,
    process_tree_stopped: bool = True,
    observed_at: datetime | None = None,
    call_id: str | None = None,
) -> StoredDataRef:
    return artifacts.put_json(
        {
            "kind": "simple_codex_cleanup_confirmation",
            "analysis_id": checkpoint.identity.analysis_id,
            "stage": checkpoint.stage.value,
            "attempt_id": checkpoint.attempt_id,
            "checkpoint_sha256": hashlib.sha256(
                canonical_bytes(checkpoint)
            ).hexdigest(),
            "process_tree_stopped": process_tree_stopped,
            "verification_method": "windows_process_inventory",
            "former_parent_pid": 12345,
            "observed_matching_process_count": 0,
            "observed_at": (
                observed_at or checkpoint.updated_at + timedelta(seconds=1)
            ).isoformat(),
            **({"call_id": call_id} if call_id is not None else {}),
        }
    )


@pytest.mark.asyncio
async def test_free_exploration_pages_are_checkpointed_and_not_repeated(
    tmp_path: Path,
) -> None:
    app, _store, _client, _hypotheses = _setup(tmp_path)
    paged = _PagedHypotheses()
    app._hypotheses = paged
    request = SimpleAnalysisRequest(
        data_dir=tmp_path / "data",
        repository="https://github.com/example/repo",
        commit="a" * 40,
    )

    first = await app.analyze(request)
    second = await app.resume("analysis-1")

    assert first.status == second.status == "COMPLETE"
    assert paged.cursors == [None, "page-1", "page-2"]


@pytest.mark.asyncio
async def test_retryable_free_page_failure_retries_only_that_page(
    tmp_path: Path,
) -> None:
    app, store, _client, _hypotheses = _setup(tmp_path)
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    request_ref = artifacts.put_json({"kind": "failed_free_page_request"})
    diagnostic_ref = artifacts.put_json({"kind": "failed_free_page_diagnostic"})

    class FlakyPages(_PagedHypotheses):
        def __init__(self) -> None:
            super().__init__()
            self.failed_once = False

        async def propose_page(
            self,
            identity: CheckpointIdentity,
            static: StaticBootstrapResult,
            *,
            after_cursor: str | None,
            page_budget_bytes: int = 32_768,
        ) -> tuple[tuple[HypothesisSeed, ...], str | None] | StageFailure:
            if after_cursor == "page-1" and not self.failed_once:
                self.failed_once = True
                self.cursors.append(after_cursor)
                return StageFailure(
                    code="FAILED",
                    retryable=True,
                    safe_message="Transient provider failure",
                    evidence_refs=(request_ref, diagnostic_ref),
                )
            return await super().propose_page(
                identity,
                static,
                after_cursor=after_cursor,
                page_budget_bytes=page_budget_bytes,
            )

    paged = FlakyPages()
    app._hypotheses = paged
    first = await app.analyze(
        SimpleAnalysisRequest(
            data_dir=tmp_path / "data",
            repository="https://github.com/example/repo",
            commit="a" * 40,
        )
    )
    second = await app.resume("analysis-1")

    assert first.status == second.status == "COMPLETE"
    assert paged.cursors == [None, "page-1", "page-1", "page-2"]
    bundle_hash = app._static.result.static_bundle_ref.content_hash
    progress = store.survey_progress("analysis-1", bundle_hash)
    assert set(progress) == {
        "__candidate_free_page_00000000__",
        "__candidate_free_page_00000001__",
        "__candidate_free_page_00000002__",
        "__candidate_free_done__",
    }
    retried_page = json.loads(
        artifacts.read(progress["__candidate_free_page_00000001__"])
    )
    assert retried_page["retry_failure_refs"] == [
        request_ref.model_dump(mode="json"),
        diagnostic_ref.model_dump(mode="json"),
    ]


@pytest.mark.asyncio
async def test_historical_invalid_free_page_resumes_without_repeating_prior_work(
    tmp_path: Path,
) -> None:
    app, store, candidate_client, _hypotheses = _setup(
        tmp_path, decision="INCLUDE", with_ast_summary=True
    )
    focused = _ManyHypotheses(tmp_path / "data")
    app._candidate_hypotheses = focused
    app._runner_factory = lambda *_: _SuccessRunner(store)

    class InvalidSecondPage(_PagedHypotheses):
        def __init__(self) -> None:
            super().__init__()
            self.repair_available = False

        async def propose_page(
            self,
            identity: CheckpointIdentity,
            static: StaticBootstrapResult,
            *,
            after_cursor: str | None,
            page_budget_bytes: int = 32_768,
        ) -> tuple[tuple[HypothesisSeed, ...], str | None] | StageFailure:
            del identity, static, page_budget_bytes
            self.cursors.append(after_cursor)
            if after_cursor == "page-1" and not self.repair_available:
                return StageFailure(
                    code="HYPOTHESIS_PAGE_OUTPUT_INVALID",
                    retryable=False,
                    safe_message="One location was outside the source page",
                )
            return (), {None: "page-1", "page-1": None}[after_cursor]

    pages = InvalidSecondPage()
    app._hypotheses = pages
    first = await app.analyze(
        SimpleAnalysisRequest(
            data_dir=tmp_path / "data",
            repository="https://github.com/example/repo",
            commit="a" * 40,
        )
    )

    assert (first.status, first.error_code) == (
        "BLOCKED",
        "HYPOTHESIS_PAGE_OUTPUT_INVALID",
    )
    run = store.require_analysis_run("analysis-1")
    assert run.static_bundle_ref is not None
    progress_before = store.survey_progress(
        "analysis-1", run.static_bundle_ref.content_hash
    )
    first_page_ref = progress_before["__candidate_free_page_00000000__"]
    prior_id = store.list_hypotheses(first.identity, limit=1)[0]
    prior_child = first.identity.model_copy(update={"hypothesis_id": prior_id})
    completed_job = StageCheckpoint(
        identity=prior_child,
        stage=SimpleStage.VERIFICATION_FINAL_DONE,
        stage_version=STAGE_VERSION[SimpleStage.VERIFICATION_FINAL_DONE],
        status=StageStatus.SUCCEEDED,
        input_refs=(),
        input_hash=input_reference_hash(()),
        verdict="FALSE",
    )
    store.save_checkpoint(completed_job)
    pages.repair_available = True

    resumed = await app.resume("analysis-1")

    assert resumed.status == "COMPLETE", resumed.error_code
    assert resumed.identity.analysis_id == first.identity.analysis_id
    assert pages.cursors == [None, "page-1", "page-1"]
    assert candidate_client.calls == focused.calls == 1
    progress_after = store.survey_progress(
        "analysis-1", run.static_bundle_ref.content_hash
    )
    assert progress_after["__candidate_free_page_00000000__"] == first_page_ref
    assert (
        store.require(prior_child, SimpleStage.VERIFICATION_FINAL_DONE) == completed_job
    )


@pytest.mark.asyncio
async def test_failed_free_page_preserves_both_attempt_refs_on_running_stage(
    tmp_path: Path,
) -> None:
    app, store, _client, _hypotheses = _setup(tmp_path)
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    first_ref = artifacts.put_json({"kind": "first_page_failure"})
    second_ref = artifacts.put_json({"kind": "second_page_failure"})

    class FailedPages(_PagedHypotheses):
        def __init__(self) -> None:
            super().__init__()
            self.running_attempt_id: str | None = None

        async def propose_page(
            self,
            _identity: CheckpointIdentity,
            _static: StaticBootstrapResult,
            *,
            after_cursor: str | None,
            page_budget_bytes: int = 32_768,
        ) -> tuple[tuple[HypothesisSeed, ...], str | None] | StageFailure:
            del page_budget_bytes
            self.cursors.append(after_cursor)
            checkpoint = store.get(identity, SimpleStage.HYPOTHESIS_DONE)
            assert checkpoint is not None
            assert checkpoint.status is StageStatus.RUNNING
            if self.running_attempt_id is None:
                self.running_attempt_id = checkpoint.attempt_id
                return StageFailure(
                    code="FAILED",
                    retryable=True,
                    safe_message="First page attempt failed",
                    evidence_refs=(first_ref,),
                )
            assert checkpoint.attempt_id == self.running_attempt_id
            return StageFailure(
                code="FAILED",
                retryable=False,
                safe_message="Second page attempt failed",
                evidence_refs=(second_ref,),
            )

    paged = FailedPages()
    app._hypotheses = paged
    outcome = await app.analyze(
        SimpleAnalysisRequest(
            data_dir=tmp_path / "data",
            repository="https://github.com/example/repo",
            commit="a" * 40,
        )
    )

    failed = store.get(identity, SimpleStage.HYPOTHESIS_DONE)
    assert outcome.status == "BLOCKED"
    assert paged.cursors == [None, None]
    assert failed is not None
    assert failed.attempt_id == paged.running_attempt_id
    assert failed.output_refs == (first_ref, second_ref)


@pytest.mark.asyncio
async def test_resume_does_not_repeat_unconfirmed_codex_process_cleanup(
    tmp_path: Path,
) -> None:
    app, _store, _client, _hypotheses = _setup(tmp_path)

    class UnconfirmedCleanup(_PagedHypotheses):
        async def propose_page(
            self,
            identity: CheckpointIdentity,
            static: StaticBootstrapResult,
            *,
            after_cursor: str | None,
            page_budget_bytes: int = 32_768,
        ) -> tuple[tuple[HypothesisSeed, ...], str | None] | StageFailure:
            del identity, static, page_budget_bytes
            self.cursors.append(after_cursor)
            return StageFailure(
                code="CODEX_PROCESS_CLEANUP_UNCONFIRMED",
                retryable=False,
                safe_message="Codex child process cleanup could not be confirmed",
            )

    paged = UnconfirmedCleanup()
    app._hypotheses = paged
    first = await app.analyze(
        SimpleAnalysisRequest(
            data_dir=tmp_path / "data",
            repository="https://github.com/example/repo",
            commit="a" * 40,
        )
    )
    second = await app.resume("analysis-1")

    assert first.status == second.status == "BLOCKED"
    assert second.error_code == "CODEX_PROCESS_CLEANUP_UNCONFIRMED"
    assert paged.cursors == [None]


@pytest.mark.asyncio
async def test_exhausted_source_page_timeout_is_not_retried_at_full_size(
    tmp_path: Path,
) -> None:
    app, _store, _client, _hypotheses = _setup(tmp_path)

    class ExhaustedPages(_PagedHypotheses):
        async def propose_page(
            self,
            identity: CheckpointIdentity,
            static: StaticBootstrapResult,
            *,
            after_cursor: str | None,
            page_budget_bytes: int = 32_768,
        ) -> tuple[tuple[HypothesisSeed, ...], str | None] | StageFailure:
            del identity, static, page_budget_bytes
            self.cursors.append(after_cursor)
            return StageFailure(
                code="HYPOTHESIS_PAGE_TIMEOUT_EXHAUSTED",
                retryable=False,
                safe_message="Source page timed out at the minimum size",
            )

    paged = ExhaustedPages()
    app._hypotheses = paged
    outcome = await app.analyze(
        SimpleAnalysisRequest(
            data_dir=tmp_path / "data",
            repository="https://github.com/example/repo",
            commit="a" * 40,
        )
    )

    assert outcome.status == "BLOCKED"
    assert outcome.error_code == "HYPOTHESIS_PAGE_TIMEOUT_EXHAUSTED"
    assert paged.cursors == [None]


@pytest.mark.asyncio
async def test_verified_codex_cleanup_can_resume_without_repeating_completed_work(
    tmp_path: Path,
) -> None:
    app, store, _client, _hypotheses = _setup(tmp_path)

    class RecoveredPages(_PagedHypotheses):
        async def propose_page(
            self,
            identity: CheckpointIdentity,
            static: StaticBootstrapResult,
            *,
            after_cursor: str | None,
            page_budget_bytes: int = 32_768,
        ) -> tuple[tuple[HypothesisSeed, ...], str | None] | StageFailure:
            del identity, static, page_budget_bytes
            self.cursors.append(after_cursor)
            if len(self.cursors) == 2:
                return StageFailure(
                    code="CODEX_PROCESS_CLEANUP_UNCONFIRMED",
                    retryable=False,
                    safe_message="Codex child process cleanup could not be confirmed",
                )
            return (), {None: "page-1", "page-1": None}[after_cursor]

    paged = RecoveredPages()
    app._hypotheses = paged
    first = await app.analyze(
        SimpleAnalysisRequest(
            data_dir=tmp_path / "data",
            repository="https://github.com/example/repo",
            commit="a" * 40,
        )
    )
    assert first.status == "BLOCKED"
    checkpoint = store.get(first.identity, SimpleStage.HYPOTHESIS_DONE)
    assert checkpoint is not None
    artifacts = SimpleArtifactRepository(tmp_path / "data", first.identity)
    audit = _cleanup_audit(artifacts, checkpoint)

    store.confirm_codex_cleanup(checkpoint, audit, artifacts)
    second = await app.resume("analysis-1")

    assert second.status == "COMPLETE"
    assert paged.cursors == [None, "page-1", "page-1"]
    assert store.has_codex_cleanup_confirmation(checkpoint, artifacts)


@pytest.mark.asyncio
async def test_resume_blocks_unresolved_codex_call_without_changing_running_checkpoint(
    tmp_path: Path,
) -> None:
    app, store, _client, _hypotheses = _setup(tmp_path)
    first = await app.analyze(
        SimpleAnalysisRequest(
            data_dir=tmp_path / "data",
            repository="https://github.com/example/repo",
            commit="a" * 40,
        )
    )
    assert first.status == "COMPLETE"
    prior = store.get(first.identity, SimpleStage.HYPOTHESIS_DONE)
    assert prior is not None
    running = store.mark_running(
        first.identity,
        SimpleStage.HYPOTHESIS_DONE,
        prior.input_refs,
        attempt_id="crashed-stage-attempt",
    )
    store.begin_codex_call("crashed-call", first.identity.analysis_id)
    before_events = store.stage_activity(
        first.identity, SimpleStage.HYPOTHESIS_DONE, "crashed-stage-attempt"
    )

    blocked = await app.resume("analysis-1")

    assert blocked.status == "BLOCKED"
    assert blocked.error_code == "CODEX_CALL_IN_FLIGHT_UNRESOLVED"
    assert blocked.current_stage is SimpleStage.HYPOTHESIS_DONE
    assert store.get(first.identity, SimpleStage.HYPOTHESIS_DONE) == running
    assert (
        store.stage_activity(
            first.identity, SimpleStage.HYPOTHESIS_DONE, "crashed-stage-attempt"
        )
        == before_events
    )

    artifacts = SimpleArtifactRepository(tmp_path / "data", first.identity)
    audit = _cleanup_audit(artifacts, running, call_id="crashed-call")
    store.confirm_codex_cleanup(running, audit, artifacts)

    assert store.unresolved_codex_call("analysis-1") is None
    assert store.get(first.identity, SimpleStage.HYPOTHESIS_DONE) == running
    assert store.has_codex_cleanup_confirmation(running, artifacts)
    after_events = store.stage_activity(
        first.identity, SimpleStage.HYPOTHESIS_DONE, "crashed-stage-attempt"
    )
    assert len(after_events) == len(before_events) + 1
    assert after_events[-1].kind.value == "DECISION_RECORDED"


@pytest.mark.asyncio
async def test_tracked_codex_cleanup_confirmation_resolves_exact_call_only(
    tmp_path: Path,
) -> None:
    app, store, _client, _hypotheses = _setup(tmp_path)

    class UnconfirmedPages(_PagedHypotheses):
        async def propose_page(
            self,
            identity: CheckpointIdentity,
            static: StaticBootstrapResult,
            *,
            after_cursor: str | None,
            page_budget_bytes: int = 32_768,
        ) -> tuple[tuple[HypothesisSeed, ...], str | None] | StageFailure:
            del identity, static, page_budget_bytes
            self.cursors.append(after_cursor)
            if len(self.cursors) == 2:
                return StageFailure(
                    code="CODEX_PROCESS_CLEANUP_UNCONFIRMED",
                    retryable=False,
                    safe_message="Codex cleanup could not be confirmed",
                )
            return (), {None: "page-1", "page-1": None}[after_cursor]

    pages = UnconfirmedPages()
    app._hypotheses = pages
    call_id = "tracked-call"
    store.begin_codex_call(call_id, "analysis-1")
    first = await app.analyze(
        SimpleAnalysisRequest(
            data_dir=tmp_path / "data",
            repository="https://github.com/example/repo",
            commit="a" * 40,
        )
    )
    assert first.status == "BLOCKED"
    checkpoint = store.get(first.identity, SimpleStage.HYPOTHESIS_DONE)
    assert checkpoint is not None
    artifacts = SimpleArtifactRepository(tmp_path / "data", first.identity)
    wrong = _cleanup_audit(artifacts, checkpoint, call_id="other-call")
    with pytest.raises(ValueError, match="CODEX_CLEANUP_CONFIRMATION_INVALID"):
        store.confirm_codex_cleanup(checkpoint, wrong, artifacts)
    assert store.unresolved_codex_call("analysis-1") == call_id

    blocked = await app.resume("analysis-1")
    assert blocked.status == "BLOCKED"
    assert blocked.error_code == "CODEX_CALL_IN_FLIGHT_UNRESOLVED"
    assert store.get(first.identity, SimpleStage.HYPOTHESIS_DONE) == checkpoint

    audit = _cleanup_audit(artifacts, checkpoint, call_id=call_id)
    usage_before = store.usage_summary("analysis-1")
    assert usage_before["calls"] == 1
    assert usage_before["unknown_token_calls"] == 1
    assert usage_before["unknown_cost_calls"] == 1
    assert usage_before["unrecorded_in_flight_codex_calls"] == 1
    store.confirm_codex_cleanup(checkpoint, audit, artifacts)
    assert store.unresolved_codex_call("analysis-1") is None
    assert store.has_codex_cleanup_confirmation(checkpoint, artifacts)
    usage = store.usage_summary("analysis-1")
    assert usage["calls"] == usage_before["calls"]
    assert usage["unknown_token_calls"] == 1
    assert usage["unknown_cost_calls"] == 1
    assert usage["unrecorded_in_flight_codex_calls"] == 0
    assert usage["unlinked_codex_usage_calls"] == 0

    resumed = await app.resume("analysis-1")
    assert resumed.status == "COMPLETE"
    assert pages.cursors == [None, "page-1", "page-1"]


@pytest.mark.asyncio
async def test_codex_cleanup_confirmation_rejects_unverified_process_tree(
    tmp_path: Path,
) -> None:
    app, store, _client, _hypotheses = _setup(tmp_path)

    class UnconfirmedCleanup(_PagedHypotheses):
        async def propose_page(
            self,
            identity: CheckpointIdentity,
            static: StaticBootstrapResult,
            *,
            after_cursor: str | None,
            page_budget_bytes: int = 32_768,
        ) -> tuple[tuple[HypothesisSeed, ...], str | None] | StageFailure:
            del identity, static, after_cursor, page_budget_bytes
            return StageFailure(
                code="CODEX_PROCESS_CLEANUP_UNCONFIRMED",
                retryable=False,
                safe_message="Codex child process cleanup could not be confirmed",
            )

    app._hypotheses = UnconfirmedCleanup()
    first = await app.analyze(
        SimpleAnalysisRequest(
            data_dir=tmp_path / "data",
            repository="https://github.com/example/repo",
            commit="a" * 40,
        )
    )
    checkpoint = store.get(first.identity, SimpleStage.HYPOTHESIS_DONE)
    assert checkpoint is not None
    artifacts = SimpleArtifactRepository(tmp_path / "data", first.identity)
    audit = _cleanup_audit(artifacts, checkpoint, process_tree_stopped=False)

    with pytest.raises(ValueError, match="CODEX_CLEANUP_CONFIRMATION_INVALID"):
        store.confirm_codex_cleanup(checkpoint, audit, artifacts)
    stale = _cleanup_audit(
        artifacts,
        checkpoint,
        observed_at=checkpoint.updated_at - timedelta(seconds=1),
    )
    with pytest.raises(ValueError, match="CODEX_CLEANUP_CONFIRMATION_INVALID"):
        store.confirm_codex_cleanup(checkpoint, stale, artifacts)
    second = await app.resume("analysis-1")

    assert second.status == "BLOCKED"
    assert second.error_code == "CODEX_PROCESS_CLEANUP_UNCONFIRMED"


@pytest.mark.asyncio
@pytest.mark.parametrize("partial", [False, True])
async def test_corrupt_free_exploration_completion_blocks_resume(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, partial: bool
) -> None:
    app, store, _client, _hypotheses = _setup(tmp_path, partial=partial)
    paged = _PagedHypotheses()
    app._hypotheses = paged
    request = SimpleAnalysisRequest(
        data_dir=tmp_path / "data",
        repository="https://github.com/example/repo",
        commit="a" * 40,
    )
    first = await app.analyze(request)
    assert first.status == ("PARTIAL" if partial else "COMPLETE")
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    wrong_ref = artifacts.put_json(
        {
            "kind": "simple_candidate_free_exploration_complete",
            "analysis_id": "analysis-1",
            "static_bundle_hash": "wrong-bundle",
            "page_count": 3,
        }
    )
    original = store.survey_progress

    def corrupted(analysis_id: str, bundle_hash: str) -> dict[str, StoredDataRef]:
        progress = original(analysis_id, bundle_hash)
        progress["__candidate_free_done__"] = wrong_ref
        return progress

    monkeypatch.setattr(store, "survey_progress", corrupted)
    second = await app.resume("analysis-1")

    assert second.status == "BLOCKED"
    assert second.error_code == "HYPOTHESIS_PAGE_CHECKPOINT_INVALID"
    assert paged.cursors == [None, "page-1", "page-2"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "corruption",
    ["missing", "kind", "analysis", "bundle", "cursor", "next_cursor", "seeds"],
)
async def test_corrupt_middle_free_page_blocks_completed_resume(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, corruption: str
) -> None:
    app, store, _client, _hypotheses = _setup(tmp_path)
    paged = _PagedHypotheses()
    app._hypotheses = paged
    request = SimpleAnalysisRequest(
        data_dir=tmp_path / "data",
        repository="https://github.com/example/repo",
        commit="a" * 40,
    )
    first = await app.analyze(request)
    assert first.status == "COMPLETE"
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    original = store.survey_progress

    def corrupted(analysis_id: str, bundle_hash: str) -> dict[str, StoredDataRef]:
        progress = original(analysis_id, bundle_hash)
        key = "__candidate_free_page_00000001__"
        original_ref = progress[key]
        if corruption == "missing":
            progress[key] = original_ref.model_copy(update={"content_hash": "0" * 64})
            return progress
        page = json.loads(artifacts.read(original_ref))
        if corruption == "kind":
            page["kind"] = "wrong"
        elif corruption == "analysis":
            page["analysis_id"] = "different-analysis"
        elif corruption == "bundle":
            page["static_bundle_hash"] = "wrong-bundle"
        elif corruption == "cursor":
            page["cursor"] = "wrong-cursor"
        elif corruption == "next_cursor":
            page["next_cursor"] = "wrong-next"
        else:
            page["seeds"] = ["not-a-seed"]
        progress[key] = artifacts.put_json(page)
        return progress

    monkeypatch.setattr(store, "survey_progress", corrupted)
    second = await app.resume("analysis-1")

    assert second.status == "BLOCKED"
    assert second.error_code == "HYPOTHESIS_PAGE_CHECKPOINT_INVALID"
    assert paged.cursors == [None, "page-1", "page-2"]


@pytest.mark.asyncio
async def test_candidate_report_coverage_refresh_uses_durable_hypothesis_rows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app, store, _client, _hypotheses = _setup(tmp_path)
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    child = identity.model_copy(update={"hypothesis_id": "hypothesis-1"})
    artifacts = SimpleArtifactRepository(tmp_path / "data", child)
    old_ref = artifacts.put_json({"coverage": "old"})
    new_ref = artifacts.put_json({"coverage": "new"})
    finding_ref = artifacts.put_json({"finding": "one"})
    manifest_ref = artifacts.put_json({"bundle": "one"})
    store.upsert_hypothesis(identity, "hypothesis-1")
    store.save_checkpoint(
        StageCheckpoint(
            identity=child,
            stage=SimpleStage.FINDING_DONE,
            status=StageStatus.SUCCEEDED,
            input_refs=(),
            input_hash=input_reference_hash(()),
            output_refs=(finding_ref,),
        )
    )
    store.save_checkpoint(
        StageCheckpoint(
            identity=child,
            stage=SimpleStage.REPORT_DONE,
            stage_version=STAGE_VERSION[SimpleStage.REPORT_DONE],
            status=StageStatus.SUCCEEDED,
            input_refs=(),
            input_hash=input_reference_hash(()),
            output_refs=(manifest_ref,),
            bundle_manifest_ref=manifest_ref,
        )
    )
    monkeypatch.setattr(
        SimpleArtifactRepository,
        "published_report_coverage",
        lambda *_args: (old_ref, "PARTIAL"),
    )
    invalidated: list[str] = []
    monkeypatch.setattr(
        store,
        "invalidate_from",
        lambda selected, *_args, **_kwargs: invalidated.append(selected.hypothesis_id),
    )
    run = SimpleAnalysisRun(
        analysis_id=identity.analysis_id,
        display_analysis_id="A-001",
        workspace_id=identity.workspace_id,
        commit_id=identity.commit_id,
        repository="https://github.com/example/repo",
        candidate_pipeline_version=1,
        static_disposition="FULL",
        static_coverage_ref=new_ref,
    )

    app._invalidate_stale_report_coverage(run, identity)

    assert invalidated == ["hypothesis-1"]


class _ManyHypotheses:
    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self.calls = 0

    async def propose(
        self, identity: CheckpointIdentity, static: StaticBootstrapResult
    ) -> tuple[HypothesisSeed, ...]:
        self.calls += 1
        artifacts = SimpleArtifactRepository(self.data_dir, identity)
        bundle = json.loads(artifacts.read(static.static_bundle_ref))
        candidate_id = bundle["candidate_focus"]["candidate_id"]
        hypothesis_id = "hypothesis-" + candidate_id
        proposal_ref = artifacts.put_json(
            {
                "kind": "simple_hypothesis_proposal",
                "analysis_id": identity.analysis_id,
                "hypothesis_id": hypothesis_id,
                "proposal": {"title": "eval input", "code_locations": ["app.py:2"]},
            }
        )
        return (
            HypothesisSeed(
                hypothesis_id=hypothesis_id,
                proposal_ref=proposal_ref,
            ),
        )


@pytest.mark.asyncio
async def test_candidate_hypothesis_bundle_contains_bounded_ast_focus(
    tmp_path: Path,
) -> None:
    app, _store, _client, _hypotheses = _setup(
        tmp_path, result_count=200, decision="INCLUDE", with_ast_summary=True
    )
    captured: list[dict[str, Any]] = []

    class CaptureHypotheses:
        async def propose(
            self, identity: CheckpointIdentity, static: StaticBootstrapResult
        ) -> tuple[HypothesisSeed, ...]:
            if not captured:
                captured.append(
                    json.loads(
                        SimpleArtifactRepository(tmp_path / "data", identity).read(
                            static.static_bundle_ref
                        )
                    )
                )
            return ()

    app._candidate_hypotheses = CaptureHypotheses()
    outcome = await app.analyze(
        SimpleAnalysisRequest(
            data_dir=tmp_path / "data",
            repository="https://github.com/example/repo",
            commit="a" * 40,
        )
    )

    assert outcome.status == "COMPLETE"
    assert len(captured) == 1
    focused_bundle = captured[0]
    ast_focus = focused_bundle["ast_focus"]
    assert ast_focus["total_count"] > len(ast_focus["facts"])
    assert any(
        fact["path"] == "app.py"
        and fact["line"] == focused_bundle["candidate_focus"]["line"]
        for fact in ast_focus["facts"]
    )
    assert len(json.dumps(ast_focus, separators=(",", ":")).encode()) <= 8192
    assert "manifest_ref" not in ast_focus
    assert len(ast_focus["facts"]) < 201
    assert "ast_summary" not in focused_bundle


@pytest.mark.asyncio
async def test_legacy_candidate_setup_without_ast_summary_still_resumes(
    tmp_path: Path,
) -> None:
    app, _store, _client, _hypotheses = _setup(tmp_path)
    outcome = await app.analyze(
        SimpleAnalysisRequest(
            data_dir=tmp_path / "data",
            repository="https://github.com/example/repo",
            commit="a" * 40,
        )
    )

    resumed = await app.resume("analysis-1")

    assert outcome.status == resumed.status == "COMPLETE"


@pytest.mark.asyncio
async def test_legacy_partial_candidate_resume_does_not_mix_new_ast_evidence(
    tmp_path: Path,
) -> None:
    app, store, _client, _hypotheses = _setup(tmp_path, partial=True)
    static = app._static
    assert isinstance(static, _Static)
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    old_bundle = json.loads(artifacts.read(static.result.static_bundle_ref))
    old_bundle["ast_summary"] = {
        "kind": "simple_python_ast",
        "facts": [],
        "parsed_file_count": 1,
        "fact_count": 0,
        "truncated": False,
    }
    old_ref = artifacts.put_json(old_bundle)
    static.result = static.result.model_copy(update={"static_bundle_ref": old_ref})
    first = await app.analyze(
        SimpleAnalysisRequest(
            data_dir=tmp_path / "data",
            repository="https://github.com/example/repo",
            commit="a" * 40,
        )
    )
    assert first.status == "PARTIAL"

    new_summary = collect_python_ast(
        tmp_path / "checkout", ("app.py",), artifacts, max_source_bytes=32_768
    )
    assert static.result.static_coverage_ref is not None
    old_coverage = json.loads(artifacts.read(static.result.static_coverage_ref))
    new_coverage = old_coverage | {"out_of_scope_product_files": []}
    new_coverage_ref = artifacts.put_json(new_coverage)
    new_bundle = old_bundle | {
        "ast_summary": new_summary,
        "static_coverage_ref": new_coverage_ref.model_dump(mode="json"),
    }
    static.result = static.result.model_copy(
        update={
            "static_bundle_ref": artifacts.put_json(new_bundle),
            "static_coverage_ref": new_coverage_ref,
            "static_disposition": "FULL",
        }
    )

    resumed = await app.resume("analysis-1")

    assert resumed.status == "PARTIAL"
    assert resumed.error_code == "AST_FORMAT_UPGRADE_NEW_ANALYSIS_REQUIRED"
    assert static.calls == 1
    assert store.require_analysis_run("analysis-1").static_bundle_ref == old_ref


@pytest.mark.asyncio
async def test_completed_candidate_resume_rejects_missing_ast_artifact(
    tmp_path: Path,
) -> None:
    app, store, _client, _hypotheses = _setup(tmp_path, with_ast_summary=True)
    outcome = await app.analyze(
        SimpleAnalysisRequest(
            data_dir=tmp_path / "data",
            repository="https://github.com/example/repo",
            commit="a" * 40,
        )
    )
    assert outcome.status == "COMPLETE"
    identity = outcome.identity
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    run = store.require_analysis_run("analysis-1")
    assert run.static_bundle_ref is not None
    bundle = json.loads(artifacts.read(run.static_bundle_ref))
    manifest = json.loads(
        artifacts.read(
            StoredDataRef.model_validate(bundle["ast_summary"]["manifest_ref"])
        )
    )
    file_ref = StoredDataRef.model_validate(manifest["entries"][0]["ref"])
    artifacts.artifacts.path_for(file_ref.content_hash).unlink()

    resumed = await app.resume("analysis-1")

    assert resumed.status == "BLOCKED"
    assert resumed.error_code == "STATIC_EVIDENCE_INVALID"


class _SuccessRunner(SimpleRuntimeRunner):
    def __init__(self, store: SimpleCheckpointStore) -> None:
        super().__init__(store, {})

    async def resume_hypothesis(self, identity: CheckpointIdentity) -> RunOutcome:
        self.store.save_checkpoint(
            StageCheckpoint(
                identity=identity,
                stage=SimpleStage.VERIFICATION_FINAL_DONE,
                stage_version=STAGE_VERSION[SimpleStage.VERIFICATION_FINAL_DONE],
                status=StageStatus.SUCCEEDED,
                input_refs=(),
                input_hash=input_reference_hash(()),
                verdict="FALSE",
            )
        )
        return RunOutcome(
            current_stage=SimpleStage.VERIFICATION_FINAL_DONE,
            status=StageStatus.SUCCEEDED,
        )


@pytest.mark.asyncio
async def test_candidate_focus_redacts_credential_shaped_excerpt_before_hypothesis(
    tmp_path: Path,
) -> None:
    fake_expression = "password = compute()"
    app, store, client, _ = _setup(
        tmp_path,
        decision="INCLUDE",
        evidence_excerpt=fake_expression,
        with_ast_summary=True,
    )

    class CaptureHypotheses(_ManyHypotheses):
        def __init__(self, data_dir: Path) -> None:
            super().__init__(data_dir)
            self.focused_ref: StoredDataRef | None = None

        async def propose(
            self, identity: CheckpointIdentity, static: StaticBootstrapResult
        ) -> tuple[HypothesisSeed, ...]:
            self.focused_ref = static.static_bundle_ref
            return await super().propose(identity, static)

    hypotheses = CaptureHypotheses(tmp_path / "data")
    app._candidate_hypotheses = hypotheses
    app._runner_factory = lambda *_: _SuccessRunner(store)

    outcome = await app.analyze(
        SimpleAnalysisRequest(
            data_dir=tmp_path / "data",
            repository="https://github.com/example/repo",
            commit="a" * 40,
        )
    )

    assert outcome.status == "COMPLETE", outcome.error_code
    assert client.calls == hypotheses.calls == 1
    assert hypotheses.focused_ref is not None
    artifacts = SimpleArtifactRepository(tmp_path / "data", outcome.identity)
    focused = json.loads(artifacts.read(hypotheses.focused_ref))
    assert focused["candidate_focus"]["evidence_excerpt"] == "[REDACTED:CREDENTIAL]"
    assert focused["candidate_focus"]["summary"] == "eval call"
    assert focused["ast_focus"]["status"] == "AVAILABLE"

    candidate = store.list_candidates(outcome.identity, "scope-1", limit=1)[0]
    assert candidate.decision == "INCLUDE"
    assert candidate.evidence_excerpt == fake_expression
    run = store.require_analysis_run("analysis-1")
    assert run.static_bundle_ref is not None
    static_bundle = json.loads(artifacts.read(run.static_bundle_ref))
    raw_ref = StoredDataRef.model_validate(static_bundle["engine_raw_refs"][0])
    raw = json.loads(artifacts.read(raw_ref))
    assert raw["results"][0]["extra"]["lines"] == fake_expression


@pytest.mark.asyncio
async def test_new_pipeline_persists_excluded_candidate_and_finishes_without_findings(
    tmp_path: Path,
) -> None:
    app, store, client, hypotheses = _setup(tmp_path)

    outcome = await app.analyze(
        SimpleAnalysisRequest(
            data_dir=tmp_path / "data",
            repository="https://github.com/example/repo",
            commit="a" * 40,
        )
    )

    assert outcome.status == "COMPLETE"
    run = store.require_analysis_run("analysis-1")
    assert run.candidate_pipeline_version == 1
    assert run.candidate_terminal is not None
    assert run.static_bundle_ref is not None
    assert run.candidate_terminal.status == "COMPLETE"
    assert run.candidate_terminal.bundle_hash == run.static_bundle_ref.content_hash
    assert run.candidate_terminal.scope_fingerprint == "scope-1"
    assert run.candidate_terminal.decision_counts["EXCLUDE"] == 1
    assert run.candidate_terminal.hypothesis_count == 0
    assert run.hypothesis_ids == ()
    assert (
        store.candidate_counts(
            CheckpointIdentity(
                analysis_id="analysis-1",
                workspace_id="workspace-1",
                commit_id="a" * 40,
                hypothesis_id=None,
            ),
            "scope-1",
        )["EXCLUDE"]
        == 1
    )
    assert client.calls == 1
    assert hypotheses.calls <= 1

    resumed = await app.resume("analysis-1")
    assert resumed.status == "COMPLETE"
    assert store.require_analysis_run("analysis-1").candidate_terminal == (
        run.candidate_terminal
    )
    assert client.calls == 1
    assert (
        store.candidate_counts(
            CheckpointIdentity(
                analysis_id="analysis-1",
                workspace_id="workspace-1",
                commit_id="a" * 40,
                hypothesis_id=None,
            ),
            "scope-1",
        )["EXCLUDE"]
        == 1
    )


@pytest.mark.asyncio
async def test_budget_pause_and_unchanged_resume_submit_no_llm_call(
    tmp_path: Path,
) -> None:
    app, store, client, _ = _setup(tmp_path, budget=True)
    request = SimpleAnalysisRequest(
        data_dir=tmp_path / "data",
        repository="https://github.com/example/repo",
        commit="a" * 40,
    )

    first = await app.analyze(request)
    second = await app.resume("analysis-1")

    assert first.status == second.status == "PAUSED"
    assert first.error_code == second.error_code == "LLM_TOKEN_BUDGET_EXHAUSTED"
    assert client.calls == 0
    assert store.require_analysis_run("analysis-1").candidate_pipeline_version == 1
    assert store.require_analysis_run("analysis-1").candidate_terminal is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure_code", ["LLM_COST_USAGE_UNAVAILABLE", "LLM_TOKEN_USAGE_UNAVAILABLE"]
)
@pytest.mark.parametrize("stage", ["candidate", "free", "downstream"])
async def test_unmeasured_usage_pauses_each_candidate_stage_on_resume(
    tmp_path: Path, failure_code: str, stage: str
) -> None:
    app, store, client, _ = _setup(
        tmp_path, decision="EXCLUDE" if stage == "free" else "INCLUDE"
    )
    failure = StageFailure(
        code=failure_code, retryable=False, safe_message="usage unavailable"
    )

    if stage == "candidate":

        class BlockedCandidateHypotheses:
            async def propose(self, *_args: object) -> StageFailure:
                return failure

        app._candidate_hypotheses = BlockedCandidateHypotheses()
    elif stage == "free":

        class BlockedFreeHypotheses:
            async def propose(
                self, _identity: CheckpointIdentity, _static: StaticBootstrapResult
            ) -> StageFailure:
                return failure

            async def propose_page(
                self, *_args: object, **_kwargs: object
            ) -> StageFailure:
                return failure

        app._hypotheses = BlockedFreeHypotheses()
    else:

        class BlockedRunner(SimpleRuntimeRunner):
            async def resume_hypothesis(
                self, _identity: CheckpointIdentity
            ) -> RunOutcome:
                return RunOutcome(
                    current_stage=SimpleStage.PRO_CON_DONE,
                    status=StageStatus.BLOCKED,
                    error_code=failure_code,
                )

        app._candidate_hypotheses = _ManyHypotheses(tmp_path / "data")
        app._runner_factory = lambda *_: BlockedRunner(store, {})

    request = SimpleAnalysisRequest(
        data_dir=tmp_path / "data",
        repository="https://github.com/example/repo",
        commit="a" * 40,
    )
    first = await app.analyze(request)
    resumed = await app.resume("analysis-1")

    assert first.status == resumed.status == "PAUSED"
    assert first.error_code == resumed.error_code == failure_code
    assert client.calls == 1
    assert store.require_analysis_run("analysis-1").candidate_pipeline_version == 1


@pytest.mark.asyncio
async def test_one_candidate_with_two_hypotheses_registers_as_one_batch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app, store, _client, _ = _setup(tmp_path, decision="INCLUDE")
    data_dir = tmp_path / "data"

    class TwoHypotheses(_ManyHypotheses):
        async def propose(
            self, identity: CheckpointIdentity, static: StaticBootstrapResult
        ) -> tuple[HypothesisSeed, ...]:
            first = await super().propose(identity, static)
            second_id = first[0].hypothesis_id + "-second"
            ref = SimpleArtifactRepository(data_dir, identity).put_json(
                {
                    "kind": "simple_hypothesis_proposal",
                    "analysis_id": identity.analysis_id,
                    "hypothesis_id": second_id,
                    "proposal": {"title": "second call path"},
                }
            )
            return first + (HypothesisSeed(hypothesis_id=second_id, proposal_ref=ref),)

    app._candidate_hypotheses = TwoHypotheses(data_dir)
    app._runner_factory = lambda *_: _SuccessRunner(store)

    def forbid_single_registration(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("candidate seeds must be committed in one transaction")

    monkeypatch.setattr(
        store, "register_candidate_hypothesis", forbid_single_registration
    )
    outcome = await app.analyze(
        SimpleAnalysisRequest(
            data_dir=data_dir,
            repository="https://github.com/example/repo",
            commit="a" * 40,
        )
    )
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    assert outcome.status == "COMPLETE", outcome.error_code
    assert store.hypothesis_count(identity) == 2
    candidate = store.list_candidates(identity, "scope-1", limit=1)[0]
    assert (
        len(
            store.list_candidate_hypothesis_ids(
                identity, "scope-1", candidate.candidate_id
            )
        )
        == 2
    )


@pytest.mark.asyncio
async def test_completed_candidate_resume_rejects_missing_original_proposal(
    tmp_path: Path,
) -> None:
    app, store, _client, _ = _setup(tmp_path, decision="INCLUDE")
    data_dir = tmp_path / "data"

    class RedactedHypotheses(_ManyHypotheses):
        async def propose(
            self, identity: CheckpointIdentity, static: StaticBootstrapResult
        ) -> tuple[HypothesisSeed, ...]:
            self.calls += 1
            artifacts = SimpleArtifactRepository(data_dir, identity)
            bundle = json.loads(artifacts.read(static.static_bundle_ref))
            hypothesis_id = "hypothesis-" + bundle["candidate_focus"]["candidate_id"]
            ref = artifacts.put_prompt_proposal(
                {
                    "kind": "simple_hypothesis_proposal",
                    "analysis_id": identity.analysis_id,
                    "hypothesis_id": hypothesis_id,
                    "proposal": {
                        "title": "Credential flow",
                        "source": "access_token = request.args.get('token')",
                        "code_locations": ["app.py:2"],
                    },
                }
            )
            return (HypothesisSeed(hypothesis_id=hypothesis_id, proposal_ref=ref),)

    app._candidate_hypotheses = RedactedHypotheses(data_dir)
    app._runner_factory = lambda *_: _SuccessRunner(store)
    first = await app.analyze(
        SimpleAnalysisRequest(
            data_dir=data_dir,
            repository="https://github.com/example/repo",
            commit="a" * 40,
        )
    )
    assert first.status == "COMPLETE"
    identity = first.identity
    hypothesis_id = store.list_hypotheses(identity, limit=1)[0]
    child = identity.model_copy(update={"hypothesis_id": hypothesis_id})
    checkpoint = store.require(child, SimpleStage.PRO_CON_DONE)
    artifacts = SimpleArtifactRepository(data_dir, identity)
    safe = json.loads(artifacts.read(checkpoint.input_refs[0]))
    original_ref = StoredDataRef.model_validate(safe["original_proposal_ref"])
    artifacts.artifacts.path_for(original_ref.content_hash).unlink()

    resumed = await app.resume(identity.analysis_id)

    assert resumed.status == "BLOCKED"
    assert resumed.error_code == "HYPOTHESIS_EVIDENCE_INVALID"


def test_completed_free_page_rejects_foreign_analysis_proposal(tmp_path: Path) -> None:
    app, _store, _client, _hypotheses = _setup(tmp_path)
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    static = app._static
    assert isinstance(static, _Static)
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    page_input_ref = artifacts.put_json(
        {
            "kind": "simple_hypothesis_source_page",
            "analysis_id": identity.analysis_id,
            "cursor": None,
        }
    )
    proposal_ref = artifacts.put_prompt_proposal(
        {
            "kind": "simple_hypothesis_proposal",
            "analysis_id": "other-analysis",
            "hypothesis_id": "hypothesis-1",
            "page_input_ref": page_input_ref.model_dump(mode="json"),
            "proposal": {"title": "Different analysis"},
        }
    )
    page_ref = artifacts.put_json(
        {
            "kind": "simple_candidate_free_exploration_page",
            "analysis_id": identity.analysis_id,
            "static_bundle_hash": static.result.static_bundle_ref.content_hash,
            "cursor": None,
            "next_cursor": None,
            "seeds": [
                HypothesisSeed(
                    hypothesis_id="hypothesis-1", proposal_ref=proposal_ref
                ).model_dump(mode="json")
            ],
        }
    )
    done_ref = artifacts.put_json(
        {
            "kind": "simple_candidate_free_exploration_complete",
            "analysis_id": identity.analysis_id,
            "static_bundle_hash": static.result.static_bundle_ref.content_hash,
            "page_count": 1,
        }
    )
    with pytest.raises(ValueError, match="HYPOTHESIS_PAGE_CHECKPOINT_INVALID"):
        app._candidate_free_done_valid(
            identity,
            static.result,
            {
                "__candidate_free_page_00000000__": page_ref,
                "__candidate_free_done__": done_ref,
            },
        )


@pytest.mark.asyncio
async def test_forty_candidates_create_forty_deep_hypotheses_without_run_json_cap(
    tmp_path: Path,
) -> None:
    app, store, client, _ = _setup(tmp_path, result_count=40, decision="INCLUDE")
    app._candidate_hypotheses = _ManyHypotheses(tmp_path / "data")
    app._runner_factory = lambda *_: _SuccessRunner(store)

    outcome = await app.analyze(
        SimpleAnalysisRequest(
            data_dir=tmp_path / "data",
            repository="https://github.com/example/repo",
            commit="a" * 40,
        )
    )

    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    assert outcome.status == "COMPLETE", outcome.error_code
    assert store.candidate_counts(identity, "scope-1")["INCLUDE"] == 40
    assert store.candidate_deep_counts(identity, "scope-1")["COMPLETE"] == 40
    assert store.hypothesis_count(identity) == 40
    first_id = store.list_hypotheses(identity, limit=1)[0]
    pro_con = store.require(
        identity.model_copy(update={"hypothesis_id": first_id}),
        SimpleStage.PRO_CON_DONE,
    )
    focused = json.loads(
        SimpleArtifactRepository(tmp_path / "data", identity).read(
            pro_con.input_refs[1]
        )
    )
    assert focused["candidate_focus"]["candidate_id"] in {
        candidate.candidate_id
        for candidate in store.list_candidates(identity, "scope-1", limit=40)
    }
    assert store.require_analysis_run("analysis-1").hypothesis_ids == ()
    assert client.calls == 5


@pytest.mark.asyncio
async def test_partial_resume_retries_static_gaps_after_deep_work_is_terminal(
    tmp_path: Path,
) -> None:
    app, store, _, _ = _setup(tmp_path, partial=True)
    request = SimpleAnalysisRequest(
        data_dir=tmp_path / "data",
        repository="https://github.com/example/repo",
        commit="a" * 40,
    )

    first = await app.analyze(request)
    second = await app.resume("analysis-1")

    assert first.status == second.status == "PARTIAL"
    static = app._static
    assert isinstance(static, _Static)
    assert static.calls == 2
    assert store.require_analysis_run("analysis-1").candidate_pipeline_version == 1


@pytest.mark.asyncio
async def test_static_retry_failure_clears_previous_partial_terminal_marker(
    tmp_path: Path,
) -> None:
    app, store, _, _ = _setup(tmp_path, partial=True)
    request = SimpleAnalysisRequest(
        data_dir=tmp_path / "data",
        repository="https://github.com/example/repo",
        commit="a" * 40,
    )
    first = await app.analyze(request)
    assert first.status == "PARTIAL"
    assert store.require_analysis_run("analysis-1").candidate_terminal is not None

    class FailedStaticRetry:
        async def run(
            self, _request: SimpleAnalysisRequest, _identity: CheckpointIdentity
        ) -> StaticBootstrapResult:
            raise RuntimeError("STATIC_RECHECK_FAILED")

    app._static = FailedStaticRetry()
    resumed = await app.resume("analysis-1")

    assert resumed.status == "BLOCKED"
    assert store.require_analysis_run("analysis-1").candidate_terminal is None


@pytest.mark.asyncio
async def test_completed_resume_error_clears_previous_terminal_marker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app, store, _, _ = _setup(tmp_path)
    request = SimpleAnalysisRequest(
        data_dir=tmp_path / "data",
        repository="https://github.com/example/repo",
        commit="a" * 40,
    )
    assert (await app.analyze(request)).status == "COMPLETE"
    assert store.require_analysis_run("analysis-1").candidate_terminal is not None

    def invalid_raw_evidence(*_args: object, **_kwargs: object) -> None:
        raise ValueError("CANDIDATE_EVIDENCE_INVALID")

    monkeypatch.setattr(
        "sastsimi.simple_runtime.application.ingest_static_candidates",
        invalid_raw_evidence,
    )
    resumed = await app.resume("analysis-1")

    assert resumed.status == "BLOCKED"
    assert store.require_analysis_run("analysis-1").candidate_terminal is None


def test_legacy_run_json_without_terminal_marker_still_loads() -> None:
    run = SimpleAnalysisRun(
        analysis_id="analysis-old",
        display_analysis_id="A-001",
        workspace_id="workspace-old",
        commit_id="a" * 40,
        repository="https://github.com/example/repo",
    )
    legacy = json.loads(run.model_dump_json())
    legacy.pop("candidate_terminal")

    restored = SimpleAnalysisRun.model_validate_json(json.dumps(legacy))

    assert restored.candidate_terminal is None
    assert restored.candidate_pipeline_version is None
