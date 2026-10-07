"""A corrected report validator may replay only its exact blocked child."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.interfaces.cli.exit_codes import ExitCode
from sastsimi.interfaces.cli.main import main
from sastsimi.reporting.analysis_display_id import AnalysisDisplayIdStore
from sastsimi.simple_runtime.application import (
    SimpleAnalysisApplication,
    SimpleAnalysisOutcome,
)
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    HYPOTHESIS_STAGES,
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
)
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.storage.agent_activity import AgentActivityStore
from tests.simple_runtime.test_legacy_import_stop_replan import _checkpoint
from tests.unit.interfaces.test_public_simple_cli import _config, _PublicApplication


def _report_content(*, legacy_ipv4: bool = True) -> dict[str, object]:
    prose = {
        "title": "A verified issue",
        "summary": "The saved evidence supports this issue.",
        "details": "The saved PoC reached the risky operation.",
        "impact": "The affected operation can be invoked.",
        "recommendation": "Validate the untrusted input.",
        "limitations": [
            "The local test server defaults to 127.0.0.1."
            if legacy_ipv4
            else "The deployment configuration needs review."
        ],
        "review_items": ["Confirm the affected deployment."],
    }
    return {"schema_version": 2, "en": prose, "ko": prose, "citations": []}


def _blocked_report(
    tmp_path: Path,
) -> tuple[
    SimpleCheckpointStore,
    SimpleArtifactRepository,
    StageCheckpoint,
    StoredDataRef,
    StageCheckpoint,
]:
    data_dir = tmp_path / "data"
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    store.save_analysis_run(
        SimpleAnalysisRun(
            analysis_id=identity.analysis_id,
            display_analysis_id="A-001",
            workspace_id=identity.workspace_id,
            commit_id=identity.commit_id,
            repository="example/repository",
            hypothesis_ids=(),
            candidate_pipeline_version=2,
        )
    )
    artifacts = SimpleArtifactRepository(data_dir, identity)
    store.upsert_hypothesis(
        identity.model_copy(update={"hypothesis_id": None}),
        identity.hypothesis_id or "",
    )
    source_refs: list[StoredDataRef] = []
    prior: dict[SimpleStage, StageCheckpoint] = {}
    for stage in HYPOTHESIS_STAGES[:-1]:
        output = artifacts.put_json({"kind": stage.value})
        checkpoint = _checkpoint(
            identity,
            stage,
            status=StageStatus.SUCCEEDED,
            inputs=(source_refs[-1],) if source_refs else (),
            outputs=(output,),
            attempt_id=f"{stage.value}-attempt",
            attempt_number=1,
        )
        if stage in {SimpleStage.VERIFICATION_FINAL_DONE, SimpleStage.FINDING_DONE}:
            checkpoint = checkpoint.model_copy(update={"verdict": "TRUE"})
        if stage is SimpleStage.POC_EXECUTION_DONE:
            checkpoint = checkpoint.model_copy(update={"validated_poc_ref": output})
        store.save_checkpoint(checkpoint)
        source_refs.append(output)
        prior[stage] = checkpoint

    stopped = _checkpoint(
        identity,
        SimpleStage.REPORT_DONE,
        status=StageStatus.BLOCKED,
        inputs=(source_refs[-1],),
        attempt_id="report-attempt-2",
        attempt_number=2,
        error_code="STAGE_UNEXPECTED_ERROR",
    )
    store.save_checkpoint(stopped)
    root_identity = identity.model_copy(update={"hypothesis_id": None})
    root = _checkpoint(
        root_identity,
        SimpleStage.HYPOTHESIS_DONE,
        status=StageStatus.BLOCKED,
        attempt_id="root-attempt",
        attempt_number=1,
        error_code=(
            "CANDIDATE_CHILD_ERROR_BOUND:STAGE_UNEXPECTED_ERROR:"
            "hypothesis-1:report-attempt-2"
        ),
    )
    store.save_checkpoint(root)
    draft_ref = artifacts.put_json(
        {
            "kind": "simple_report_draft",
            "source_refs": [ref.model_dump(mode="json") for ref in source_refs],
            "result": _report_content(),
            "prompt_digest": "b" * 64,
            "output_digest": hashlib.sha256(
                canonical_bytes(_report_content())
            ).hexdigest(),
            "attempt_id": stopped.attempt_id,
        }
    )
    other_identity = identity.model_copy(update={"hypothesis_id": "hypothesis-2"})
    other_report = _checkpoint(
        other_identity,
        SimpleStage.REPORT_DONE,
        status=StageStatus.SUCCEEDED,
        outputs=(artifacts.put_json({"kind": "other-report"}),),
        attempt_id="other-report-attempt",
        attempt_number=1,
    )
    store.save_checkpoint(other_report)
    return store, artifacts, stopped, draft_ref, other_report


def test_exact_report_validator_replay_preserves_other_work(tmp_path: Path) -> None:
    store, artifacts, stopped, draft_ref, other_report = _blocked_report(tmp_path)
    identity = stopped.identity
    prior = store.prior(identity, SimpleStage.REPORT_DONE)
    root_identity = identity.model_copy(update={"hypothesis_id": None})
    root_before = store.require(root_identity, SimpleStage.HYPOTHESIS_DONE)

    pending = store.prepare_report_validator_replay(stopped, draft_ref, artifacts)

    assert pending.status is StageStatus.PENDING
    assert pending.stage is SimpleStage.REPORT_DONE
    assert pending.attempt_number == 2
    assert pending.attempt_id is None
    assert pending.input_refs == stopped.input_refs
    assert store.require(identity, SimpleStage.REPORT_DONE) == pending
    assert store.prior(identity, SimpleStage.REPORT_DONE) == prior
    assert store.require(root_identity, SimpleStage.HYPOTHESIS_DONE) == root_before
    assert store.require(other_report.identity, SimpleStage.REPORT_DONE) == other_report
    source_hash = hashlib.sha256(
        canonical_bytes(
            {
                "refs": tuple(item.output_refs[0] for item in prior.values()),
                "finding_attempt_id": prior[SimpleStage.FINDING_DONE].attempt_id,
                "poc_attempt_id": prior[SimpleStage.POC_EXECUTION_DONE].attempt_id,
            }
        )
    ).hexdigest()
    assert (
        store.report_draft(
            identity, source_hash, prior[SimpleStage.FINDING_DONE].output_refs[0]
        )
        == draft_ref
    )


def test_legacy_unexpected_error_rejects_unrelated_valid_report(
    tmp_path: Path,
) -> None:
    store, artifacts, stopped, _draft_ref, _ = _blocked_report(tmp_path)
    result = _report_content(legacy_ipv4=False)
    prior = store.prior(stopped.identity, SimpleStage.REPORT_DONE)
    refs = tuple(item.output_refs[0] for item in prior.values())
    draft_ref = artifacts.put_json(
        {
            "kind": "simple_report_draft",
            "source_refs": [ref.model_dump(mode="json") for ref in refs],
            "result": result,
            "prompt_digest": "b" * 64,
            "output_digest": hashlib.sha256(canonical_bytes(result)).hexdigest(),
            "attempt_id": stopped.attempt_id,
        }
    )

    with pytest.raises(
        ValueError, match="REPORT_VALIDATOR_REPLAY_LEGACY_CAUSE_UNPROVEN"
    ):
        store.prepare_report_validator_replay(stopped, draft_ref, artifacts)
    assert store.require(stopped.identity, SimpleStage.REPORT_DONE) == stopped


def test_explicit_metadata_claim_error_does_not_need_legacy_ipv4(
    tmp_path: Path,
) -> None:
    store, artifacts, stopped, _draft_ref, _ = _blocked_report(tmp_path)
    stopped = stopped.model_copy(
        update={"error_code": "REPORT_UNSUPPORTED_METADATA_CLAIM"}
    )
    store.save_checkpoint(stopped)
    root_identity = stopped.identity.model_copy(update={"hypothesis_id": None})
    root = store.require(root_identity, SimpleStage.HYPOTHESIS_DONE)
    store.save_checkpoint(
        root.model_copy(
            update={
                "error_code": (
                    "CANDIDATE_CHILD_ERROR_BOUND:REPORT_UNSUPPORTED_METADATA_CLAIM:"
                    "hypothesis-1:report-attempt-2"
                )
            }
        )
    )
    result = _report_content(legacy_ipv4=False)
    refs = tuple(
        item.output_refs[0]
        for item in store.prior(stopped.identity, SimpleStage.REPORT_DONE).values()
    )
    draft_ref = artifacts.put_json(
        {
            "kind": "simple_report_draft",
            "source_refs": [ref.model_dump(mode="json") for ref in refs],
            "result": result,
            "prompt_digest": "b" * 64,
            "output_digest": hashlib.sha256(canonical_bytes(result)).hexdigest(),
            "attempt_id": stopped.attempt_id,
        }
    )

    pending = store.prepare_report_validator_replay(stopped, draft_ref, artifacts)
    assert pending.status is StageStatus.PENDING


@pytest.mark.parametrize("invalid", ["root", "draft", "inflight", "stale"])
def test_report_validator_replay_rejects_unbound_or_unverified_state(
    tmp_path: Path, invalid: str
) -> None:
    store, artifacts, stopped, draft_ref, _ = _blocked_report(tmp_path)
    original = store.require(stopped.identity, SimpleStage.REPORT_DONE)
    if invalid == "root":
        root_identity = stopped.identity.model_copy(update={"hypothesis_id": None})
        root = store.require(root_identity, SimpleStage.HYPOTHESIS_DONE)
        store.save_checkpoint(root.model_copy(update={"error_code": "OTHER_CHILD"}))
    elif invalid == "draft":
        draft_ref = artifacts.put_json(
            {
                "kind": "simple_report_draft",
                "attempt_id": stopped.attempt_id,
                "source_refs": [],
                "result": _report_content(),
                "prompt_digest": "b" * 64,
                "output_digest": hashlib.sha256(
                    canonical_bytes(_report_content())
                ).hexdigest(),
            }
        )
    elif invalid == "inflight":
        assert store.begin_codex_call("unfinished-call", stopped.identity.analysis_id)
    else:
        store.save_checkpoint(stopped.model_copy(update={"attempt_id": "new-attempt"}))

    with pytest.raises(ValueError, match="REPORT_VALIDATOR_REPLAY_"):
        store.prepare_report_validator_replay(stopped, draft_ref, artifacts)

    current = store.require(stopped.identity, SimpleStage.REPORT_DONE)
    assert current == (
        stopped.model_copy(update={"attempt_id": "new-attempt"})
        if invalid == "stale"
        else original
    )


def test_report_validator_replay_rejects_unsupported_draft_claim(
    tmp_path: Path,
) -> None:
    store, artifacts, stopped, _draft_ref, _ = _blocked_report(tmp_path)
    result = _report_content()
    english = result["en"]
    assert isinstance(english, dict)
    result["en"] = {**english, "summary": "Affected versions 1.2.3"}
    prior = store.prior(stopped.identity, SimpleStage.REPORT_DONE)
    refs = tuple(item.output_refs[0] for item in prior.values())
    draft_ref = artifacts.put_json(
        {
            "kind": "simple_report_draft",
            "source_refs": [ref.model_dump(mode="json") for ref in refs],
            "result": result,
            "prompt_digest": "b" * 64,
            "output_digest": hashlib.sha256(canonical_bytes(result)).hexdigest(),
            "attempt_id": stopped.attempt_id,
        }
    )

    with pytest.raises(ValueError, match="REPORT_VALIDATOR_REPLAY_DRAFT_INVALID"):
        store.prepare_report_validator_replay(stopped, draft_ref, artifacts)
    assert store.require(stopped.identity, SimpleStage.REPORT_DONE) == stopped


def test_report_validator_replay_rolls_back_cache_checkpoint_and_event(
    tmp_path: Path,
) -> None:
    store, artifacts, stopped, draft_ref, _ = _blocked_report(tmp_path)
    ledger = AgentActivityStore(store.database_path)
    before = ledger.list_analysis(
        stopped.identity.analysis_id, hypothesis_id=stopped.identity.hypothesis_id
    )
    with pytest.raises(RuntimeError, match="simulated crash"):
        store.prepare_report_validator_replay(
            stopped, draft_ref, artifacts, fail_before_commit=True
        )
    assert store.require(stopped.identity, SimpleStage.REPORT_DONE) == stopped
    assert (
        ledger.list_analysis(
            stopped.identity.analysis_id, hypothesis_id=stopped.identity.hypothesis_id
        )
        == before
    )
    prior = store.prior(stopped.identity, SimpleStage.REPORT_DONE)
    source_hash = hashlib.sha256(
        canonical_bytes(
            {
                "refs": tuple(item.output_refs[0] for item in prior.values()),
                "finding_attempt_id": prior[SimpleStage.FINDING_DONE].attempt_id,
                "poc_attempt_id": prior[SimpleStage.POC_EXECUTION_DONE].attempt_id,
            }
        )
    ).hexdigest()
    assert (
        store.report_draft(
            stopped.identity,
            source_hash,
            prior[SimpleStage.FINDING_DONE].output_refs[0],
        )
        is None
    )


@pytest.mark.asyncio
async def test_application_replays_only_unique_bound_report_draft(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, artifacts, stopped, draft_ref, other_report = _blocked_report(tmp_path)
    identity = stopped.identity
    AnalysisDisplayIdStore(store.database_path).get_or_allocate(identity.analysis_id)
    older = artifacts.put_json(
        {
            "kind": "simple_report_draft",
            "attempt_id": "report-attempt-1",
            "source_refs": [],
            "result": _report_content(),
        }
    )
    application = SimpleAnalysisApplication(
        data_dir=tmp_path / "data",
        store=store,
        static_bootstrap=None,  # type: ignore[arg-type]
        hypothesis_bootstrap=None,  # type: ignore[arg-type]
        runner_factory=None,  # type: ignore[arg-type]
    )

    async def resume_locked(_analysis_id: str) -> SimpleAnalysisOutcome:
        return SimpleAnalysisOutcome(
            identity=identity.model_copy(update={"hypothesis_id": None}),
            display_analysis_id="A-001",
            status="RUNNING",
            current_stage=SimpleStage.REPORT_DONE,
        )

    monkeypatch.setattr(application, "_resume_locked", resume_locked)
    await application.resume(
        identity.analysis_id,
        repair_report_validator_hypothesis=identity.hypothesis_id,
    )
    assert (
        store.require(identity, SimpleStage.REPORT_DONE).status is StageStatus.PENDING
    )
    assert store.require(other_report.identity, SimpleStage.REPORT_DONE) == other_report
    assert older != draft_ref


@pytest.mark.asyncio
async def test_application_rejects_ambiguous_bound_report_drafts(
    tmp_path: Path,
) -> None:
    store, artifacts, stopped, _draft_ref, _other_report = _blocked_report(tmp_path)
    identity = stopped.identity
    AnalysisDisplayIdStore(store.database_path).get_or_allocate(identity.analysis_id)
    artifacts.put_json(
        {
            "kind": "simple_report_draft",
            "attempt_id": stopped.attempt_id,
            "source_refs": [],
            "result": _report_content(),
        }
    )
    application = SimpleAnalysisApplication(
        data_dir=tmp_path / "data",
        store=store,
        static_bootstrap=None,  # type: ignore[arg-type]
        hypothesis_bootstrap=None,  # type: ignore[arg-type]
        runner_factory=None,  # type: ignore[arg-type]
    )
    with pytest.raises(ValueError, match="REPORT_VALIDATOR_REPLAY_DRAFT_AMBIGUOUS"):
        await application.resume(
            identity.analysis_id,
            repair_report_validator_hypothesis=identity.hypothesis_id,
        )
    assert store.require(identity, SimpleStage.REPORT_DONE) == stopped


def test_cli_forwards_report_validator_replay_flag(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    class _Application(_PublicApplication):
        def __init__(self) -> None:
            self.seen: list[tuple[str, str | None]] = []

        def resume(
            self,
            analysis_id: str,
            *,
            repair_report_validator_hypothesis: str | None = None,
            **_kwargs: object,
        ) -> dict[str, object]:
            self.seen.append(("plain", repair_report_validator_hypothesis))
            return {"analysis_id": analysis_id, "status": "RUNNING"}

        def resume_with_progress(
            self,
            analysis_id: str,
            _callback: object,
            *,
            repair_report_validator_hypothesis: str | None = None,
            **_kwargs: object,
        ) -> dict[str, object]:
            self.seen.append(("progress", repair_report_validator_hypothesis))
            return {"analysis_id": analysis_id, "status": "RUNNING"}

    application = _Application()
    for extra, label in [(["--format", "json"], "plain"), ([], "progress")]:
        assert main(
            [
                "resume",
                "A-001",
                "--repair-report-validator",
                "hypothesis-1",
                *extra,
            ],
            public_application=application,
            user_config_store=_config(tmp_path),
        ) == int(ExitCode.OK)
        assert application.seen[-1] == (label, "hypothesis-1")
        capsys.readouterr()
