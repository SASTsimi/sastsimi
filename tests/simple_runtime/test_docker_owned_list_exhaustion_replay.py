"""One explicit replay is allowed only before a PoC container was created."""

from __future__ import annotations

import hashlib
from pathlib import Path
from uuid import uuid4

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.interfaces.cli.exit_codes import ExitCode
from sastsimi.interfaces.cli.main import main
from sastsimi.observability.agent_activity import ActivityKind
from sastsimi.reporting.analysis_display_id import AnalysisDisplayIdStore
from sastsimi.simple_runtime.application import (
    SimpleAnalysisApplication,
    SimpleAnalysisOutcome,
)
from sastsimi.simple_runtime.models import (
    SimpleStage,
    StageFailure,
    StageStatus,
)
from sastsimi.simple_runtime.stages import PoCCandidateStage
from sastsimi.storage.agent_activity import AgentActivityStore
from tests.simple_runtime.test_legacy_import_stop_replan import (
    _checkpoint,
    _PinnedStaticStub,
    _seed,
)
from tests.unit.interfaces.test_public_simple_cli import _config, _PublicApplication


def _exhausted_before_container(tmp_path: Path):  # type: ignore[no-untyped-def]
    store, artifacts, prior, _ = _seed(
        tmp_path, stderr=b"TypeError: old PoC harness failure\n"
    )
    identity = prior.identity
    candidate = store.require(identity, SimpleStage.POC_CANDIDATE_DONE)
    content_ref = candidate.output_refs[1]
    candidate_ref = artifacts.put_json(
        {
            "kind": "simple_poc_candidate",
            "attempt_id": "attempt-3",
            "content_ref": content_ref.model_dump(mode="json"),
            "content_digest": hashlib.sha256(artifacts.read(content_ref)).hexdigest(),
        }
    )
    candidate = candidate.model_copy(
        update={
            "attempt_id": "attempt-3",
            "attempt_number": 3,
            "output_refs": (candidate_ref, content_ref),
            "container_id": None,
        }
    )
    store.save_checkpoint(candidate)
    execution_inputs = (candidate_ref, content_ref)
    pending = _checkpoint(
        identity,
        SimpleStage.POC_EXECUTION_DONE,
        status=StageStatus.PENDING,
        inputs=execution_inputs,
        attempt_number=2,
        recipe_ref=candidate.recipe_ref,
        image_digest=candidate.image_digest,
    )
    store.save_checkpoint(pending)
    running = store.mark_running(
        identity,
        SimpleStage.POC_EXECUTION_DONE,
        execution_inputs,
        attempt_id="attempt-3",
        inherit_from=candidate,
    )
    failed = store.mark_failure(
        running,
        StageFailure(
            code="DOCKER_OWNED_LIST_FAILED",
            retryable=True,
            safe_message="Owned container list failed before create",
        ),
        StageStatus.BLOCKED,
    )
    exhausted = store.mark_recovery_exhausted(failed)
    root_identity = identity.model_copy(update={"hypothesis_id": None})
    root = store.require(root_identity, SimpleStage.HYPOTHESIS_DONE)
    root_running = root.model_copy(
        update={
            "status": StageStatus.RUNNING,
            "attempt_id": "root-attempt-3",
            "error_code": None,
            "retryable": False,
        }
    )
    store.save_checkpoint(root_running)
    store.mark_failure(
        root_running,
        StageFailure(
            code=(
                "CANDIDATE_CHILD_ERROR_BOUND:RECOVERY_EXHAUSTED:"
                f"{identity.hypothesis_id}:attempt-3"
            ),
            retryable=False,
            safe_message="Child PoC has exhausted automatic recovery",
        ),
        StageStatus.BLOCKED,
    )
    proof_ref = artifacts.put_json(
        {
            "kind": "simple_owned_attempt_container_absence",
            "identity": identity.model_dump(mode="json"),
            "attempt_id": exhausted.attempt_id,
            "present": False,
            "exhausted_checkpoint_hash": hashlib.sha256(
                canonical_bytes(exhausted.model_dump(mode="json"))
            ).hexdigest(),
        }
    )
    return store, artifacts, exhausted, proof_ref


def test_explicit_docker_list_exhaustion_replays_candidate_execution_pair_once(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted, proof_ref = _exhausted_before_container(tmp_path)
    identity = exhausted.identity
    previous_candidate_ref = store.require(
        identity, SimpleStage.POC_CANDIDATE_DONE
    ).output_refs[0]
    before = AgentActivityStore(store.database_path).list_analysis(
        identity.analysis_id, hypothesis_id=identity.hypothesis_id
    )

    pending = store.prepare_pre_execution_docker_replay(exhausted, proof_ref, artifacts)

    assert pending.stage is SimpleStage.POC_CANDIDATE_DONE
    assert pending.status is StageStatus.PENDING
    assert pending.attempt_number == 2
    assert pending.container_id is None
    assert pending.output_refs == ()
    assert proof_ref in pending.input_refs
    candidate_stage = PoCCandidateStage(client=None, artifacts=artifacts)  # type: ignore[arg-type]
    assert candidate_stage._current_repair_refs(pending.input_refs) == (
        previous_candidate_ref,
    )
    assert store.get(identity, SimpleStage.POC_EXECUTION_DONE) is None
    assert (
        store.require(identity, SimpleStage.VERIFICATION_INITIAL_DONE).status
        is StageStatus.SUCCEEDED
    )
    after = AgentActivityStore(store.database_path).list_analysis(
        identity.analysis_id, hypothesis_id=identity.hypothesis_id
    )
    assert len(after) == len(before) + 1
    assert any(
        event.kind is ActivityKind.DECISION_RECORDED
        and event.error_code == "DOCKER_OWNED_LIST_EXHAUSTION_REPLAYED"
        for event in after
    )
    next_candidate = store.mark_running(
        identity,
        SimpleStage.POC_CANDIDATE_DONE,
        pending.input_refs,
        attempt_id="replay-attempt-3",
    )
    assert next_candidate.attempt_number == 3
    assert next_candidate.attempt_id != exhausted.attempt_id
    with pytest.raises(ValueError, match="DOCKER_LIST_EXHAUSTION_"):
        store.prepare_pre_execution_docker_replay(exhausted, proof_ref, artifacts)


@pytest.mark.parametrize(
    "checkpoint_change",
    [
        {"attempt_number": 2},
        {"output_refs": "proof"},
        {"container_id": "existing-container"},
        {"status": StageStatus.SUCCEEDED},
        {"error_code": "POC_EXECUTION_FAILED"},
    ],
)
def test_docker_list_replay_rejects_nonexact_exhaustion(
    tmp_path: Path, checkpoint_change: dict[str, object]
) -> None:
    store, artifacts, exhausted, proof_ref = _exhausted_before_container(tmp_path)
    if checkpoint_change.get("output_refs") == "proof":
        checkpoint_change = {"output_refs": (proof_ref,)}
    modified = exhausted.model_copy(update=checkpoint_change)
    store.save_checkpoint(modified)
    with pytest.raises(ValueError, match="DOCKER_LIST_EXHAUSTION_"):
        store.prepare_pre_execution_docker_replay(modified, proof_ref, artifacts)


def test_docker_list_replay_rejects_container_presence_proof(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted, _ = _exhausted_before_container(tmp_path)
    present_ref = artifacts.put_json(
        {
            "kind": "simple_owned_attempt_container_absence",
            "identity": exhausted.identity.model_dump(mode="json"),
            "attempt_id": exhausted.attempt_id,
            "present": True,
            "exhausted_checkpoint_hash": hashlib.sha256(
                canonical_bytes(exhausted.model_dump(mode="json"))
            ).hexdigest(),
        }
    )
    with pytest.raises(ValueError, match="DOCKER_LIST_EXHAUSTION_"):
        store.prepare_pre_execution_docker_replay(exhausted, present_ref, artifacts)


def test_docker_list_replay_rejects_stale_absence_proof(tmp_path: Path) -> None:
    store, artifacts, exhausted, _ = _exhausted_before_container(tmp_path)
    stale_ref = artifacts.put_json(
        {
            "kind": "simple_owned_attempt_container_absence",
            "identity": exhausted.identity.model_dump(mode="json"),
            "attempt_id": exhausted.attempt_id,
            "present": False,
            "exhausted_checkpoint_hash": "0" * 64,
        }
    )
    with pytest.raises(ValueError, match="DOCKER_LIST_EXHAUSTION_ABSENCE_INVALID"):
        store.prepare_pre_execution_docker_replay(exhausted, stale_ref, artifacts)


def test_docker_list_replay_rejects_candidate_with_inherited_container(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted, proof_ref = _exhausted_before_container(tmp_path)
    candidate = store.require(exhausted.identity, SimpleStage.POC_CANDIDATE_DONE)
    store.save_checkpoint(
        candidate.model_copy(update={"container_id": "earlier-container"})
    )
    with pytest.raises(ValueError, match="DOCKER_LIST_EXHAUSTION_LINEAGE_INVALID"):
        store.prepare_pre_execution_docker_replay(exhausted, proof_ref, artifacts)


def test_docker_list_replay_rejects_unbound_root(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted, proof_ref = _exhausted_before_container(tmp_path)
    root_identity = exhausted.identity.model_copy(update={"hypothesis_id": None})
    root = store.require(root_identity, SimpleStage.HYPOTHESIS_DONE)
    store.save_checkpoint(root.model_copy(update={"error_code": "other-child"}))
    with pytest.raises(ValueError, match="DOCKER_LIST_EXHAUSTION_ROOT_BOUND_INVALID"):
        store.prepare_pre_execution_docker_replay(exhausted, proof_ref, artifacts)


@pytest.mark.parametrize("kind", ["extra_event", "prior_replay"])
def test_docker_list_replay_rejects_ambiguous_or_replayed_history(
    tmp_path: Path, kind: str
) -> None:
    store, artifacts, exhausted, proof_ref = _exhausted_before_container(tmp_path)
    events = store.stage_activity(
        exhausted.identity, SimpleStage.POC_EXECUTION_DONE, exhausted.attempt_id
    )
    anchor = next(event for event in events if event.kind is ActivityKind.STAGE_BLOCKED)
    added = anchor.model_copy(
        update={
            "event_id": uuid4().hex,
            "sequence": 9_999,
            "kind": (
                ActivityKind.TOOL_COMPLETED
                if kind == "extra_event"
                else ActivityKind.DECISION_RECORDED
            ),
            "error_code": (
                None
                if kind == "extra_event"
                else "DOCKER_OWNED_LIST_EXHAUSTION_REPLAYED"
            ),
        }
    )
    AgentActivityStore(store.database_path).append(added)
    with pytest.raises(ValueError, match="DOCKER_LIST_EXHAUSTION_"):
        store.prepare_pre_execution_docker_replay(exhausted, proof_ref, artifacts)


def test_docker_list_replay_rolls_back_checkpoint_and_marker_together(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted, proof_ref = _exhausted_before_container(tmp_path)
    identity = exhausted.identity
    candidate = store.require(identity, SimpleStage.POC_CANDIDATE_DONE)
    before = AgentActivityStore(store.database_path).list_analysis(
        identity.analysis_id, hypothesis_id=identity.hypothesis_id
    )
    with pytest.raises(RuntimeError, match="simulated crash"):
        store.prepare_pre_execution_docker_replay(
            exhausted, proof_ref, artifacts, fail_before_commit=True
        )
    assert store.require(identity, SimpleStage.POC_CANDIDATE_DONE) == candidate
    assert store.require(identity, SimpleStage.POC_EXECUTION_DONE) == exhausted
    assert (
        AgentActivityStore(store.database_path).list_analysis(
            identity.analysis_id, hypothesis_id=identity.hypothesis_id
        )
        == before
    )


@pytest.mark.asyncio
async def test_application_checks_exact_docker_owner_absence_before_reseed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _artifacts, exhausted, _proof_ref = _exhausted_before_container(tmp_path)
    identity = exhausted.identity
    AnalysisDisplayIdStore(store.database_path).get_or_allocate(identity.analysis_id)
    checked: list[tuple[object, str]] = []

    async def owned_attempt_container(owner: object, attempt_id: str) -> bool:
        checked.append((owner, attempt_id))
        return False

    application = SimpleAnalysisApplication(
        data_dir=tmp_path / "data",
        store=store,
        static_bootstrap=_PinnedStaticStub(tmp_path / "data" / "workspaces"),
        hypothesis_bootstrap=None,  # type: ignore[arg-type]
        runner_factory=None,  # type: ignore[arg-type]
        owned_attempt_container=owned_attempt_container,
    )

    async def static_scope(*_args: object) -> None:
        return None

    async def resume_locked(_analysis_id: str) -> SimpleAnalysisOutcome:
        return SimpleAnalysisOutcome(
            identity=identity.model_copy(update={"hypothesis_id": None}),
            display_analysis_id="A-001",
            status="RUNNING",
            current_stage=SimpleStage.POC_CANDIDATE_DONE,
        )

    monkeypatch.setattr(application, "_assert_completed_static_scope", static_scope)
    monkeypatch.setattr(application, "_resume_locked", resume_locked)
    monkeypatch.setattr(
        application, "_verify_registered_candidate_proposals", lambda _root: None
    )
    await application.resume(identity.analysis_id)
    assert store.require(identity, SimpleStage.POC_EXECUTION_DONE) == exhausted
    await application.resume(
        identity.analysis_id,
        repair_docker_owned_list_exhaustion_hypothesis=identity.hypothesis_id,
    )
    assert checked == [(identity, "attempt-3")]
    assert (
        store.require(identity, SimpleStage.POC_CANDIDATE_DONE).status
        is StageStatus.PENDING
    )
    assert store.get(identity, SimpleStage.POC_EXECUTION_DONE) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("presence", [True, RuntimeError("Docker unavailable")])
async def test_application_keeps_exhaustion_when_docker_absence_is_unverified(
    tmp_path: Path,
    presence: bool | RuntimeError,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, _artifacts, exhausted, _proof_ref = _exhausted_before_container(tmp_path)
    identity = exhausted.identity
    AnalysisDisplayIdStore(store.database_path).get_or_allocate(identity.analysis_id)

    checked: list[tuple[object, str]] = []

    async def owned_attempt_container(owner: object, attempt_id: str) -> bool:
        checked.append((owner, attempt_id))
        if isinstance(presence, RuntimeError):
            raise presence
        return presence

    application = SimpleAnalysisApplication(
        data_dir=tmp_path / "data",
        store=store,
        static_bootstrap=_PinnedStaticStub(tmp_path / "data" / "workspaces"),
        hypothesis_bootstrap=None,  # type: ignore[arg-type]
        runner_factory=None,  # type: ignore[arg-type]
        owned_attempt_container=owned_attempt_container,
    )

    async def static_scope(*_args: object) -> None:
        return None

    monkeypatch.setattr(application, "_assert_completed_static_scope", static_scope)
    monkeypatch.setattr(
        application, "_verify_registered_candidate_proposals", lambda _root: None
    )
    with pytest.raises(
        ValueError,
        match=(
            "DOCKER_LIST_EXHAUSTION_PRESENCE_UNVERIFIED"
            if isinstance(presence, RuntimeError)
            else "DOCKER_LIST_EXHAUSTION_CONTAINER_PRESENT"
        ),
    ):
        await application.resume(
            identity.analysis_id,
            repair_docker_owned_list_exhaustion_hypothesis=identity.hypothesis_id,
        )
    assert checked == [(identity, "attempt-3")]
    assert store.require(identity, SimpleStage.POC_EXECUTION_DONE) == exhausted


def test_cli_forwards_explicit_docker_list_replay_flag(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    class _Application(_PublicApplication):
        def __init__(self) -> None:
            self.seen: list[tuple[str, str | None]] = []

        def resume(
            self,
            analysis_id: str,
            *,
            repair_exhausted_hypothesis: str | None = None,
            repair_legacy_import_stop_hypothesis: str | None = None,
            repair_fallback_poc_stop_hypothesis: str | None = None,
            repair_docker_owned_list_exhaustion_hypothesis: str | None = None,
            repair_poc_placeholder_exhaustion_hypothesis: str | None = None,
            repair_poc_sensitive_content_hypothesis: str | None = None,
            repair_report_validator_hypothesis: str | None = None,
        ) -> dict[str, object]:
            del (
                repair_exhausted_hypothesis,
                repair_legacy_import_stop_hypothesis,
                repair_fallback_poc_stop_hypothesis,
                repair_poc_placeholder_exhaustion_hypothesis,
                repair_poc_sensitive_content_hypothesis,
                repair_report_validator_hypothesis,
            )
            assert analysis_id == "A-001"
            self.seen.append(("plain", repair_docker_owned_list_exhaustion_hypothesis))
            return {"analysis_id": analysis_id, "status": "RUNNING"}

        def resume_with_progress(
            self,
            analysis_id: str,
            _callback: object,
            *,
            repair_exhausted_hypothesis: str | None = None,
            repair_legacy_import_stop_hypothesis: str | None = None,
            repair_fallback_poc_stop_hypothesis: str | None = None,
            repair_docker_owned_list_exhaustion_hypothesis: str | None = None,
        ) -> dict[str, object]:
            del (
                repair_exhausted_hypothesis,
                repair_legacy_import_stop_hypothesis,
                repair_fallback_poc_stop_hypothesis,
            )
            self.seen.append(
                ("progress", repair_docker_owned_list_exhaustion_hypothesis)
            )
            return {"analysis_id": analysis_id, "status": "RUNNING"}

    application = _Application()
    assert main(
        [
            "resume",
            "A-001",
            "--repair-docker-owned-list-exhaustion",
            "hypothesis-1",
            "--format",
            "json",
        ],
        public_application=application,
        user_config_store=_config(tmp_path),
    ) == int(ExitCode.OK)
    assert application.seen == [("plain", "hypothesis-1")]
    assert "RUNNING" in capsys.readouterr().out
    assert main(
        [
            "resume",
            "A-001",
            "--repair-docker-owned-list-exhaustion",
            "hypothesis-1",
        ],
        public_application=application,
        user_config_store=_config(tmp_path),
    ) == int(ExitCode.OK)
    assert application.seen == [
        ("plain", "hypothesis-1"),
        ("progress", "hypothesis-1"),
    ]
