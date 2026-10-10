"""An explicitly requested PoC anchor replay reaches only a pinned failed child."""

from __future__ import annotations

import asyncio
import hashlib
import json
import subprocess
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace

import pytest

import sastsimi.composition.simple_runtime_composition as composition
import sastsimi.simple_runtime.application as application_module
from sastsimi.interfaces.cli.exit_codes import ExitCode
from sastsimi.interfaces.cli.main import main
from sastsimi.progress.models import ProgressSnapshot
from sastsimi.reporting.analysis_display_id import AnalysisDisplayIdStore
from sastsimi.simple_runtime.application import (
    SimpleAnalysisApplication,
    SimpleAnalysisOutcome,
)
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageFailure,
    StageResult,
    StageStatus,
)
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from tests.simple_runtime.test_legacy_import_stop_replan import (
    _checkpoint,
    _PinnedStaticStub,
)
from tests.unit.interfaces.test_public_simple_cli import _config, _PublicApplication
from tests.unit.simple_runtime.test_recovery_composition import (
    _config as _composition_config,
)
from tests.unit.simple_runtime.test_recovery_composition import _profile


def test_cli_forwards_anchor_replay_in_plain_and_progress_modes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    class Application(_PublicApplication):
        def __init__(self) -> None:
            self.seen: list[tuple[str, str | None]] = []

        def resume(
            self,
            analysis_id: str,
            *,
            repair_poc_anchor_hypothesis: str | None = None,
            **_kwargs: object,
        ) -> dict[str, object]:
            self.seen.append(("plain", repair_poc_anchor_hypothesis))
            return {"analysis_id": analysis_id, "status": "RUNNING"}

        def resume_with_progress(
            self,
            analysis_id: str,
            _callback: object,
            *,
            repair_poc_anchor_hypothesis: str | None = None,
            **_kwargs: object,
        ) -> dict[str, object]:
            self.seen.append(("progress", repair_poc_anchor_hypothesis))
            return {"analysis_id": analysis_id, "status": "RUNNING"}

    application = Application()
    for extra, route in ((["--format", "json"], "plain"), ([], "progress")):
        assert main(
            ["resume", "A-001", "--repair-poc-anchor", "hypothesis-1", *extra],
            public_application=application,
            user_config_store=_config(tmp_path),
        ) == int(ExitCode.OK)
        assert application.seen[-1] == (route, "hypothesis-1")
        capsys.readouterr()


@pytest.mark.parametrize("with_progress", [False, True])
def test_public_wrapper_forwards_anchor_replay_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, with_progress: bool
) -> None:
    public = composition.PublicSimpleRuntimeApplication(
        _composition_config(tmp_path), _profile(tmp_path)
    )
    seen: list[tuple[str, str | None]] = []
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    outcome = SimpleAnalysisOutcome(
        identity=identity,
        display_analysis_id="A-001",
        status="FAILED",
        current_stage=SimpleStage.POC_CANDIDATE_DONE,
    )

    class Application:
        async def resume(
            self,
            analysis_id: str,
            *,
            repair_poc_anchor_hypothesis: str | None = None,
            **_kwargs: object,
        ) -> SimpleAnalysisOutcome:
            seen.append((analysis_id, repair_poc_anchor_hypothesis))
            return outcome

    async def track(
        task: asyncio.Task[SimpleAnalysisOutcome],
        _started: list[str],
        _callback: Callable[[ProgressSnapshot], None],
    ) -> SimpleAnalysisOutcome:
        return await task

    monkeypatch.setattr(
        composition, "build_analysis_application", lambda *_args: Application()
    )
    monkeypatch.setattr(public._display, "resolve", lambda _id: "analysis-1")
    monkeypatch.setattr(
        public._store,
        "require_analysis_run",
        lambda _id: SimpleNamespace(
            repository="https://example.invalid/repo", commit_id="a" * 40
        ),
    )
    monkeypatch.setattr(public, "_resume_outcome", lambda *_args: {"status": "FAILED"})
    monkeypatch.setattr(public, "_track", track)

    if with_progress:
        public.resume_with_progress(
            "A-001",
            lambda _snapshot: None,
            repair_poc_anchor_hypothesis="hypothesis-1",
        )
    else:
        public.resume("A-001", repair_poc_anchor_hypothesis="hypothesis-1")
    assert seen == [("analysis-1" if with_progress else "A-001", "hypothesis-1")]


def _failed_anchor_application(
    tmp_path: Path,
    *,
    source_hash_mismatch: bool = False,
    attempt_number: int = 3,
    broken_recipe: bool = False,
) -> tuple[SimpleAnalysisApplication, StageCheckpoint]:
    workspace = tmp_path / "data" / "workspaces" / "workspace-1"
    workspace.mkdir(parents=True)
    source = b"def endpoint(request):\n    return dangerous(request.GET['name'])\n"
    (workspace / "web.py").write_bytes(source)
    subprocess.run(["git", "init", "--quiet", str(workspace)], check=True)
    subprocess.run(["git", "-C", str(workspace), "add", "web.py"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(workspace),
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "fixture",
        ],
        check=True,
    )
    commit = subprocess.run(
        ["git", "-C", str(workspace), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id=commit,
        hypothesis_id="hypothesis-1",
    )
    store = SimpleCheckpointStore(tmp_path / "data" / "db" / "sastsimi.sqlite3")
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    profile_ref = artifacts.put_json({"kind": "simple_repository_profile"})
    coverage_ref = artifacts.put_json(
        {
            "kind": "simple_static_coverage_v1",
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "fingerprint": "fingerprint-1",
            "expected_count": 1,
            "verified_count": 1,
            "gaps": [],
            "unsupported": [],
        }
    )
    manifest_ref = artifacts.put_json(
        {"kind": "simple_tracked_sources", "paths": ["web.py"]}
    )
    static_ref = artifacts.put_json(
        {
            "kind": "simple_static_fact_bundle",
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "static_coverage_ref": coverage_ref.model_dump(mode="json"),
            "source_manifest_ref": manifest_ref.model_dump(mode="json"),
        }
    )
    store.save_analysis_run(
        SimpleAnalysisRun(
            analysis_id=identity.analysis_id,
            display_analysis_id="A-001",
            workspace_id=identity.workspace_id,
            commit_id=identity.commit_id,
            repository="example/vulnerable",
            workspace_path=workspace,
            repository_profile_ref=profile_ref,
            static_bundle_ref=static_ref,
            static_coverage_ref=coverage_ref,
            candidate_scope_fingerprint="fingerprint-1",
            candidate_pipeline_version=2,
            hypothesis_ids=(identity.hypothesis_id or "",),
        )
    )
    (workspace / ".sastsimi-ready.json").write_text(
        json.dumps({"repository": "example/vulnerable", "commit": commit}),
        encoding="utf-8",
    )
    root = identity.model_copy(update={"hypothesis_id": None})
    store.save_checkpoint(
        _checkpoint(
            root,
            SimpleStage.STATIC_DONE,
            status=StageStatus.SUCCEEDED,
            outputs=(profile_ref, static_ref),
        )
    )
    AnalysisDisplayIdStore(store.database_path).get_or_allocate(identity.analysis_id)
    source_ref = artifacts.put_json(
        {
            "kind": "simple_candidate_file_context_v1",
            "path": "web.py",
            "source_status": "AVAILABLE",
            "source_sha256": (
                "0" * 64 if source_hash_mismatch else hashlib.sha256(source).hexdigest()
            ),
            "source_lines": [
                {"line": 1, "text": "def endpoint(request):"},
                {"line": 2, "text": "    return dangerous(request.GET['name'])"},
            ],
        }
    )
    proposal_ref = artifacts.put_prompt_proposal(
        {
            "kind": "simple_hypothesis_proposal",
            "analysis_id": identity.analysis_id,
            "hypothesis_id": identity.hypothesis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "shared_context_ref": source_ref.model_dump(mode="json"),
            "proposal": {"code_locations": ["web.py:2"]},
        }
    )
    store.upsert_hypothesis(root, identity.hypothesis_id or "", proposal_ref)
    inputs = (proposal_ref, source_ref)
    store.save_checkpoint(
        _checkpoint(
            identity,
            SimpleStage.PRO_CON_DONE,
            status=StageStatus.SUCCEEDED,
            inputs=inputs,
            outputs=(artifacts.put_json({"kind": "pro_con"}),),
        )
    )
    initial_ref = artifacts.put_json({"kind": "initial"})
    store.save_checkpoint(
        _checkpoint(
            identity,
            SimpleStage.VERIFICATION_INITIAL_DONE,
            status=StageStatus.SUCCEEDED,
            inputs=(artifacts.put_json({"kind": "pro_con_input"}),),
            outputs=(initial_ref,),
        )
    )
    replay_decision_ref = None
    if attempt_number >= 4:
        replay_decision_ref = artifacts.put_json(
            {
                "kind": "simple_recovery_decision",
                "identity": identity.model_dump(mode="json"),
                "stage": SimpleStage.POC_CANDIDATE_DONE.value,
                "attempt": 2,
                "attempt_id": "sensitive-attempt-2",
                "original_error": StageFailure(
                    code="POC_SENSITIVE_CONTENT",
                    retryable=True,
                    safe_message="PoC candidate was rejected",
                ).model_dump(mode="json"),
                "decision": {
                    "category": "GENERATED_INPUT",
                    "action": "STOP",
                    "diagnosis": "Repeated content validation failure",
                    "guidance": "Preserve failed candidate",
                },
                "decision_origin": "AGENT",
            }
        )
    candidate_inputs = (
        (initial_ref, replay_decision_ref)
        if replay_decision_ref is not None
        else (initial_ref,)
    )
    recipe_ref = artifacts.put_json({"kind": "simple_environment_recipe"})
    if broken_recipe:
        recipe_ref = recipe_ref.model_copy(
            update={"stored_data_id": "f" * 64, "content_hash": "f" * 64}
        )
    candidate = _checkpoint(
        identity,
        SimpleStage.POC_CANDIDATE_DONE,
        status=StageStatus.PENDING,
        inputs=candidate_inputs,
        attempt_number=attempt_number - 1,
        recipe_ref=recipe_ref,
    )
    if replay_decision_ref is not None:
        candidate = candidate.model_copy(
            update={
                "recovery_origin_stage": SimpleStage.POC_CANDIDATE_DONE,
                "recovery_decision_refs": (replay_decision_ref,),
            }
        )
    store.save_checkpoint(candidate)
    running = store.mark_running(
        identity,
        SimpleStage.POC_CANDIDATE_DONE,
        candidate_inputs,
        attempt_id="anchor-attempt-3",
    )
    stopped = store.mark_failure(
        running,
        StageFailure(
            code="HYPOTHESIS_ANCHOR_INVALID",
            retryable=False,
            safe_message="Could not validate pinned hypothesis anchor",
        ),
        StageStatus.FAILED,
    )
    running_root = store.mark_running(
        root, SimpleStage.HYPOTHESIS_DONE, (), attempt_id="root-anchor-attempt"
    )
    store.mark_failure(
        running_root,
        StageFailure(
            code=(
                "CANDIDATE_CHILD_ERROR_BOUND:HYPOTHESIS_ANCHOR_INVALID:"
                f"{identity.hypothesis_id}:{stopped.attempt_id}"
            ),
            retryable=False,
            safe_message="Candidate child analysis failed",
        ),
        StageStatus.FAILED,
    )
    application = SimpleAnalysisApplication(
        data_dir=tmp_path / "data",
        store=store,
        static_bootstrap=_PinnedStaticStub(tmp_path / "data" / "workspaces"),
        hypothesis_bootstrap=None,  # type: ignore[arg-type]
        runner_factory=None,  # type: ignore[arg-type]
    )
    return application, stopped


def test_application_anchor_replay_is_explicit_and_conflicts_with_other_repairs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    application, stopped = _failed_anchor_application(tmp_path)
    seen: list[tuple[str, str]] = []

    async def bound(_analysis_id: str, hypothesis_id: str, *, mode: str) -> None:
        seen.append((hypothesis_id, mode))

    async def resume_locked(_analysis_id: str) -> SimpleAnalysisOutcome:
        return SimpleAnalysisOutcome(
            identity=stopped.identity.model_copy(update={"hypothesis_id": None}),
            display_analysis_id="A-001",
            status="FAILED",
            current_stage=SimpleStage.POC_CANDIDATE_DONE,
        )

    monkeypatch.setattr(application, "_prepare_bound_fallback_stop_locked", bound)
    monkeypatch.setattr(application, "_resume_locked", resume_locked)
    asyncio.run(application.resume(stopped.identity.analysis_id))
    assert seen == []
    asyncio.run(
        application.resume(
            stopped.identity.analysis_id,
            repair_poc_anchor_hypothesis=stopped.identity.hypothesis_id,
        )
    )
    assert seen == [(stopped.identity.hypothesis_id, "anchor")]
    with pytest.raises(ValueError, match="LEGACY_IMPORT_STOP_REPAIR_CONFLICT"):
        asyncio.run(
            application.resume(
                stopped.identity.analysis_id,
                repair_poc_anchor_hypothesis=stopped.identity.hypothesis_id,
                repair_poc_sensitive_content_hypothesis=stopped.identity.hypothesis_id,
            )
        )


@pytest.mark.parametrize("source_hash_mismatch", [False, True])
def test_application_validates_saved_anchor_before_one_shot_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source_hash_mismatch: bool,
) -> None:
    application, stopped = _failed_anchor_application(
        tmp_path, source_hash_mismatch=source_hash_mismatch
    )
    seen: list[StageCheckpoint] = []

    def prepare(checkpoint: StageCheckpoint, _artifacts: object) -> None:
        seen.append(checkpoint)

    monkeypatch.setattr(
        application._store, "prepare_poc_anchor_failure_replay", prepare, raising=False
    )
    if source_hash_mismatch:
        with pytest.raises(ValueError, match="POC_ANCHOR_REPLAY_ANCHOR_INVALID"):
            asyncio.run(
                application._prepare_bound_fallback_stop_locked(
                    stopped.identity.analysis_id,
                    stopped.identity.hypothesis_id or "",
                    mode="anchor",
                )
            )
        assert seen == []
        assert application._store.require(stopped.identity, stopped.stage) == stopped
    else:
        asyncio.run(
            application._prepare_bound_fallback_stop_locked(
                stopped.identity.analysis_id,
                stopped.identity.hypothesis_id or "",
                mode="anchor",
            )
        )
        assert seen == [stopped]


def test_attempt_four_requires_full_candidate_pre_provider_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    application, stopped = _failed_anchor_application(
        tmp_path, attempt_number=4, broken_recipe=True
    )
    seen: list[StageCheckpoint] = []
    monkeypatch.setattr(
        application._store,
        "prepare_poc_anchor_failure_replay",
        lambda checkpoint, _artifacts: seen.append(checkpoint),
        raising=False,
    )

    with pytest.raises(ValueError, match="POC_ANCHOR_REPLAY_PRE_PROVIDER_INVALID"):
        asyncio.run(
            application._prepare_bound_fallback_stop_locked(
                stopped.identity.analysis_id,
                stopped.identity.hypothesis_id or "",
                mode="anchor",
            )
        )

    assert seen == []
    assert application._store.require(stopped.identity, stopped.stage) == stopped


def test_attempt_four_valid_candidate_context_reaches_one_shot_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    application, stopped = _failed_anchor_application(tmp_path, attempt_number=4)
    seen: list[StageCheckpoint] = []
    monkeypatch.setattr(
        application._store,
        "prepare_poc_anchor_failure_replay",
        lambda checkpoint, _artifacts: seen.append(checkpoint),
        raising=False,
    )

    asyncio.run(
        application._prepare_bound_fallback_stop_locked(
            stopped.identity.analysis_id,
            stopped.identity.hypothesis_id or "",
            mode="anchor",
        )
    )

    assert seen == [stopped]
    assert application._store.require(stopped.identity, stopped.stage) == stopped


def test_attempt_four_preflight_checks_the_next_running_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    application, stopped = _failed_anchor_application(tmp_path, attempt_number=4)
    inspected: list[StageCheckpoint] = []
    prepared: list[StageCheckpoint] = []

    class CapturingStage:
        def __init__(self, **_kwargs: object) -> None:
            pass

        async def __call__(
            self, checkpoint: StageCheckpoint, _prior: object
        ) -> StageResult:
            inspected.append(checkpoint)
            raise application_module._PoCProviderBoundaryReached

    monkeypatch.setattr(application_module, "PoCCandidateStage", CapturingStage)
    monkeypatch.setattr(
        application._store,
        "prepare_poc_anchor_failure_replay",
        lambda checkpoint, _artifacts: prepared.append(checkpoint),
        raising=False,
    )

    asyncio.run(
        application._prepare_bound_fallback_stop_locked(
            stopped.identity.analysis_id,
            stopped.identity.hypothesis_id or "",
            mode="anchor",
        )
    )

    assert len(inspected) == 1
    assert inspected[0].attempt_number == 5
    assert inspected[0].status is StageStatus.RUNNING
    assert inspected[0].attempt_id and inspected[0].attempt_id != stopped.attempt_id
    assert inspected[0].input_refs == stopped.input_refs
    assert prepared == [stopped]
    assert application._store.require(stopped.identity, stopped.stage) == stopped


@pytest.mark.parametrize("stage_outcome", ["returned", "raised"])
def test_attempt_four_rejects_without_exact_provider_boundary_sentinel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stage_outcome: str
) -> None:
    application, stopped = _failed_anchor_application(tmp_path, attempt_number=4)
    seen: list[StageCheckpoint] = []
    inspected: list[StageCheckpoint] = []
    monkeypatch.setattr(
        application._store,
        "prepare_poc_anchor_failure_replay",
        lambda checkpoint, _artifacts: seen.append(checkpoint),
        raising=False,
    )

    class UnexpectedStage:
        def __init__(self, **_kwargs: object) -> None:
            pass

        async def __call__(
            self, checkpoint: StageCheckpoint, _prior: object
        ) -> StageResult:
            inspected.append(checkpoint)
            if stage_outcome == "returned":
                return StageResult(output_refs=())
            raise RuntimeError("pre-provider setup failed")

    monkeypatch.setattr(application_module, "PoCCandidateStage", UnexpectedStage)

    with pytest.raises(ValueError, match="POC_ANCHOR_REPLAY_PRE_PROVIDER_INVALID"):
        asyncio.run(
            application._prepare_bound_fallback_stop_locked(
                stopped.identity.analysis_id,
                stopped.identity.hypothesis_id or "",
                mode="anchor",
            )
        )

    assert seen == []
    assert [checkpoint.attempt_number for checkpoint in inspected] == [5]
    assert application._store.require(stopped.identity, stopped.stage) == stopped


def test_attempt_five_checks_next_attempt_six_before_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    application, stopped = _failed_anchor_application(tmp_path, attempt_number=5)
    assert stopped.attempt_number == 5
    inspected: list[int] = []

    class ProbeStage:
        def __init__(self, **_kwargs: object) -> None:
            pass

        async def __call__(
            self, checkpoint: StageCheckpoint, _prior: object
        ) -> StageResult:
            inspected.append(checkpoint.attempt_number)
            raise RuntimeError("next candidate setup still fails")

    monkeypatch.setattr(application_module, "PoCCandidateStage", ProbeStage)
    monkeypatch.setattr(
        application._store,
        "prepare_poc_anchor_failure_replay",
        lambda *_args: pytest.fail(
            "store must not reopen before attempt-six preflight"
        ),
    )

    with pytest.raises(ValueError, match="POC_ANCHOR_REPLAY_PRE_PROVIDER_INVALID"):
        asyncio.run(
            application._prepare_bound_fallback_stop_locked(
                stopped.identity.analysis_id,
                stopped.identity.hypothesis_id or "",
                mode="anchor",
            )
        )
    assert inspected == [6]
    assert application._store.require(stopped.identity, stopped.stage) == stopped
