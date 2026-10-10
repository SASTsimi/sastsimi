"""A corrected PoC validator may explicitly re-evaluate only its exact child."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from uuid import uuid4

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.poc_candidate import POC_CANDIDATE_VALIDATOR_REVISION
from sastsimi.contracts.refs import StoredDataRef
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
    StageCheckpoint,
    StageFailure,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.storage.agent_activity import AgentActivityStore
from tests.simple_runtime.test_legacy_import_stop_replan import (
    _checkpoint,
    _PinnedStaticStub,
    _seed,
)
from tests.unit.interfaces.test_public_simple_cli import _config, _PublicApplication


def _placeholder_exhaustion(tmp_path: Path):  # type: ignore[no-untyped-def]
    store, artifacts, prior, _ = _seed(tmp_path)
    identity = prior.identity
    candidate = store.require(identity, SimpleStage.POC_CANDIDATE_DONE)
    pending = candidate.model_copy(
        update={
            "status": StageStatus.PENDING,
            "attempt_id": None,
            "attempt_number": 2,
            "output_refs": (),
            "error_code": None,
            "retryable": False,
        }
    )
    store.replace_from(pending)
    running = store.mark_running(
        identity,
        SimpleStage.POC_CANDIDATE_DONE,
        pending.input_refs,
        attempt_id="candidate-attempt-3",
    )
    failed = store.mark_failure(
        running,
        StageFailure(
            code="POC_PLACEHOLDER_FORBIDDEN",
            retryable=True,
            safe_message="Candidate rejected by local validator",
        ),
        StageStatus.BLOCKED,
    )
    exhausted = store.mark_recovery_exhausted(failed)
    root_identity = identity.model_copy(update={"hypothesis_id": None})
    root = store.require(root_identity, SimpleStage.HYPOTHESIS_DONE)
    root_running = root.model_copy(
        update={
            "status": StageStatus.RUNNING,
            "attempt_id": "root-candidate-attempt-3",
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
                f"{identity.hypothesis_id}:candidate-attempt-3"
            ),
            retryable=False,
            safe_message="Candidate generation exhausted automatic recovery",
        ),
        StageStatus.BLOCKED,
    )
    return store, artifacts, exhausted


def _fail_replayed_candidate(
    store: SimpleCheckpointStore,
    exhausted: StageCheckpoint,
    diagnostic_ref: StoredDataRef | None = None,
) -> StageCheckpoint:
    identity = exhausted.identity
    pending = store.require(identity, SimpleStage.POC_CANDIDATE_DONE)
    running = store.mark_running(
        identity,
        SimpleStage.POC_CANDIDATE_DONE,
        pending.input_refs,
        attempt_id=uuid4().hex,
    )
    failed = store.mark_failure(
        running,
        StageFailure(
            code="POC_PLACEHOLDER_FORBIDDEN",
            retryable=True,
            safe_message="Candidate rejected by local validator",
            evidence_refs=(diagnostic_ref,) if diagnostic_ref is not None else (),
        ),
        StageStatus.BLOCKED,
    )
    exhausted_again = store.mark_recovery_exhausted(failed)
    root_identity = identity.model_copy(update={"hypothesis_id": None})
    old_root = store.require(root_identity, SimpleStage.HYPOTHESIS_DONE)
    root_running = old_root.model_copy(
        update={
            "status": StageStatus.RUNNING,
            "attempt_id": uuid4().hex,
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
                f"{identity.hypothesis_id}:{exhausted_again.attempt_id}"
            ),
            retryable=False,
            safe_message="Candidate generation exhausted automatic recovery",
        ),
        StageStatus.BLOCKED,
    )
    return exhausted_again


def _legacy_replayed_exhaustion(  # type: ignore[no-untyped-def]
    tmp_path: Path, marker_extra: dict[str, object] | None = None
):
    store, artifacts, exhausted = _placeholder_exhaustion(tmp_path)
    validator_event = next(
        event
        for event in AgentActivityStore(store.database_path).list_analysis(
            exhausted.identity.analysis_id,
            hypothesis_id=exhausted.identity.hypothesis_id,
        )
        if event.stage == SimpleStage.POC_CANDIDATE_DONE.value
        and event.attempt_id == exhausted.attempt_id
        and event.error_code == "POC_PLACEHOLDER_FORBIDDEN"
    )
    old_marker = artifacts.put_json(
        {
            "kind": "simple_poc_placeholder_exhaustion_replay",
            "identity": exhausted.identity.model_dump(mode="json"),
            "old_attempt_id": exhausted.attempt_id,
            "old_attempt_number": exhausted.attempt_number,
            "exhausted_checkpoint_hash": hashlib.sha256(
                canonical_bytes(exhausted.model_dump(mode="json"))
            ).hexdigest(),
            "validator_error_event_id": validator_event.event_id,
            "reason": "POC_PLACEHOLDER_FORBIDDEN_AFTER_VALIDATOR_FIX",
            **(marker_extra or {}),
        }
    )
    AgentActivityStore(store.database_path).append(
        store._lifecycle_event(
            exhausted,
            ActivityKind.DECISION_RECORDED,
            sequence=store._stage_sequence(exhausted.stage, 102),
            status=StageStatus.BLOCKED,
            summary_ko="검증기 오류 PoC 후보만 명시적으로 재실행합니다.",
            output_refs=(old_marker,),
            error_code="POC_PLACEHOLDER_EXHAUSTION_REPLAYED",
        )
    )
    inputs = (*exhausted.input_refs, old_marker)
    pending = exhausted.model_copy(
        update={
            "status": StageStatus.PENDING,
            "input_refs": inputs,
            "input_hash": input_reference_hash(inputs),
            "attempt_id": None,
            "attempt_number": 2,
            "error_code": None,
            "retryable": False,
        }
    )
    store.save_checkpoint(pending)
    return store, artifacts, _fail_replayed_candidate(store, exhausted), old_marker


def test_exact_placeholder_validator_exhaustion_reseeds_only_candidate(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _placeholder_exhaustion(tmp_path)
    identity = exhausted.identity
    original_initial = store.require(identity, SimpleStage.VERIFICATION_INITIAL_DONE)
    before = AgentActivityStore(store.database_path).list_analysis(
        identity.analysis_id, hypothesis_id=identity.hypothesis_id
    )

    pending = store.prepare_poc_placeholder_exhaustion_replay(exhausted, artifacts)

    assert pending.stage is SimpleStage.POC_CANDIDATE_DONE
    assert pending.status is StageStatus.PENDING
    assert pending.attempt_number == 2
    assert pending.recipe_ref == exhausted.recipe_ref
    assert pending.image_digest == exhausted.image_digest
    assert pending.output_refs == ()
    assert pending.input_refs[: len(exhausted.input_refs)] == exhausted.input_refs
    assert pending.gate_revision_count == exhausted.gate_revision_count
    assert (
        store.require(identity, SimpleStage.VERIFICATION_INITIAL_DONE)
        == original_initial
    )
    assert store.get(identity, SimpleStage.POC_EXECUTION_DONE) is None
    after = AgentActivityStore(store.database_path).list_analysis(
        identity.analysis_id, hypothesis_id=identity.hypothesis_id
    )
    assert len(after) == len(before) + 1
    assert any(
        event.kind is ActivityKind.DECISION_RECORDED
        and event.error_code == "POC_PLACEHOLDER_EXHAUSTION_REPLAYED"
        for event in after
    )
    next_candidate = store.mark_running(
        identity,
        SimpleStage.POC_CANDIDATE_DONE,
        pending.input_refs,
        attempt_id="new-candidate-attempt-3",
    )
    assert next_candidate.attempt_number == 3
    assert next_candidate.attempt_id != exhausted.attempt_id
    with pytest.raises(ValueError, match="POC_PLACEHOLDER_EXHAUSTION_"):
        store.prepare_poc_placeholder_exhaustion_replay(exhausted, artifacts)


def test_first_replay_records_current_validator_revision(tmp_path: Path) -> None:
    store, artifacts, exhausted = _placeholder_exhaustion(tmp_path)

    pending = store.prepare_poc_placeholder_exhaustion_replay(exhausted, artifacts)

    marker = json.loads(artifacts.read(pending.input_refs[-1]))
    assert marker["validator_revision"] == POC_CANDIDATE_VALIDATOR_REVISION


def test_legacy_first_replay_allows_second_exact_replay_without_old_diagnostic(
    tmp_path: Path,
) -> None:
    store, artifacts, second_exhausted, old_marker = _legacy_replayed_exhaustion(
        tmp_path
    )
    assert second_exhausted.output_refs == ()

    pending = store.prepare_poc_placeholder_exhaustion_replay(
        second_exhausted, artifacts
    )

    assert pending.status is StageStatus.PENDING
    assert pending.attempt_number == 2
    assert old_marker in pending.input_refs
    assert json.loads(artifacts.read(pending.input_refs[-1]))["validator_revision"] == (
        POC_CANDIDATE_VALIDATOR_REVISION
    )


def test_same_validator_revision_cannot_replay_again_after_second_exhaustion(
    tmp_path: Path,
) -> None:
    store, artifacts, second_exhausted, _ = _legacy_replayed_exhaustion(tmp_path)
    store.prepare_poc_placeholder_exhaustion_replay(second_exhausted, artifacts)
    diagnostic_ref = artifacts.put_json(
        {
            "kind": "simple_poc_candidate_rejection_diagnostic",
            "reason": "INCONCLUSIVE_EXIT2_UNPROVEN",
            "line_count": 5,
            "branch_count": 1,
            "inconclusive_line_count": 1,
            "exit_two_line_count": 1,
            "exit_zero_line_count": 0,
        }
    )
    third_exhausted = _fail_replayed_candidate(store, second_exhausted, diagnostic_ref)

    with pytest.raises(
        ValueError, match="POC_PLACEHOLDER_EXHAUSTION_REVISION_ALREADY_REPLAYED"
    ):
        store.prepare_poc_placeholder_exhaustion_replay(third_exhausted, artifacts)


def test_legacy_second_replay_rejects_missing_prior_marker_binding(
    tmp_path: Path,
) -> None:
    store, artifacts, second_exhausted, _ = _legacy_replayed_exhaustion(tmp_path)
    tampered = second_exhausted.model_copy(
        update={"input_refs": (), "input_hash": input_reference_hash(())}
    )
    store.save_checkpoint(tampered)
    with pytest.raises(ValueError, match="POC_PLACEHOLDER_EXHAUSTION_MARKER_INVALID"):
        store.prepare_poc_placeholder_exhaustion_replay(tampered, artifacts)


def test_legacy_replay_rejects_marker_with_extra_raw_content(tmp_path: Path) -> None:
    store, artifacts, second_exhausted, _ = _legacy_replayed_exhaustion(
        tmp_path, marker_extra={"raw_content": "must not survive"}
    )
    with pytest.raises(ValueError, match="POC_PLACEHOLDER_EXHAUSTION_MARKER_INVALID"):
        store.prepare_poc_placeholder_exhaustion_replay(second_exhausted, artifacts)


def test_new_revision_replay_requires_safe_diagnostic_after_first_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, artifacts, first_exhausted = _placeholder_exhaustion(tmp_path)
    store.prepare_poc_placeholder_exhaustion_replay(first_exhausted, artifacts)
    second_exhausted = _fail_replayed_candidate(store, first_exhausted)
    monkeypatch.setattr(
        "sastsimi.simple_runtime.store.POC_CANDIDATE_VALIDATOR_REVISION",
        f"{POC_CANDIDATE_VALIDATOR_REVISION}-next",
    )

    with pytest.raises(
        ValueError, match="POC_PLACEHOLDER_EXHAUSTION_DIAGNOSTIC_MISSING"
    ):
        store.prepare_poc_placeholder_exhaustion_replay(second_exhausted, artifacts)


def test_new_revision_replay_rejects_diagnostic_with_raw_content(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, artifacts, first_exhausted = _placeholder_exhaustion(tmp_path)
    store.prepare_poc_placeholder_exhaustion_replay(first_exhausted, artifacts)
    raw_ref = artifacts.put_json(
        {
            "kind": "simple_poc_candidate_rejection_diagnostic",
            "reason": "INCONCLUSIVE_EXIT2_UNPROVEN",
            "line_count": 4,
            "branch_count": 0,
            "inconclusive_line_count": 1,
            "exit_two_line_count": 1,
            "exit_zero_line_count": 0,
            "raw_content": "must never be stored",
        }
    )
    second_exhausted = _fail_replayed_candidate(store, first_exhausted, raw_ref)
    monkeypatch.setattr(
        "sastsimi.simple_runtime.store.POC_CANDIDATE_VALIDATOR_REVISION",
        f"{POC_CANDIDATE_VALIDATOR_REVISION}-next",
    )

    with pytest.raises(
        ValueError, match="POC_PLACEHOLDER_EXHAUSTION_DIAGNOSTIC_INVALID"
    ):
        store.prepare_poc_placeholder_exhaustion_replay(second_exhausted, artifacts)


def test_changed_validator_revision_can_replay_with_safe_diagnostic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, artifacts, first_exhausted = _placeholder_exhaustion(tmp_path)
    store.prepare_poc_placeholder_exhaustion_replay(first_exhausted, artifacts)
    diagnostic_ref = artifacts.put_json(
        {
            "kind": "simple_poc_candidate_rejection_diagnostic",
            "reason": "INCONCLUSIVE_EXIT2_UNPROVEN",
            "line_count": 4,
            "branch_count": 0,
            "inconclusive_line_count": 1,
            "exit_two_line_count": 1,
            "exit_zero_line_count": 0,
        }
    )
    second_exhausted = _fail_replayed_candidate(store, first_exhausted, diagnostic_ref)
    monkeypatch.setattr(
        "sastsimi.simple_runtime.store.POC_CANDIDATE_VALIDATOR_REVISION",
        f"{POC_CANDIDATE_VALIDATOR_REVISION}-next",
    )

    pending = store.prepare_poc_placeholder_exhaustion_replay(
        second_exhausted, artifacts
    )

    assert pending.status is StageStatus.PENDING
    assert json.loads(artifacts.read(pending.input_refs[-1]))["validator_revision"] == (
        f"{POC_CANDIDATE_VALIDATOR_REVISION}-next"
    )


@pytest.mark.parametrize(
    "change",
    [
        {"error_code": "ANOTHER_ERROR"},
        {"attempt_number": 2},
        {"container_id": "owned-container"},
        {"recipe_ref": None},
        {"output_refs": "existing-output"},
    ],
)
def test_placeholder_replay_rejects_nonexact_candidate_checkpoint(
    tmp_path: Path, change: dict[str, object]
) -> None:
    store, artifacts, exhausted = _placeholder_exhaustion(tmp_path)
    if change.get("output_refs") == "existing-output":
        change = {"output_refs": (artifacts.put_json({"kind": "existing"}),)}
    modified = exhausted.model_copy(update=change)
    store.save_checkpoint(modified)
    with pytest.raises(ValueError, match="POC_PLACEHOLDER_EXHAUSTION_"):
        store.prepare_poc_placeholder_exhaustion_replay(modified, artifacts)


def test_placeholder_replay_rejects_unbound_root(tmp_path: Path) -> None:
    store, artifacts, exhausted = _placeholder_exhaustion(tmp_path)
    root_identity = exhausted.identity.model_copy(update={"hypothesis_id": None})
    root = store.require(root_identity, SimpleStage.HYPOTHESIS_DONE)
    store.save_checkpoint(root.model_copy(update={"error_code": "other-child"}))
    with pytest.raises(
        ValueError, match="POC_PLACEHOLDER_EXHAUSTION_ROOT_BOUND_INVALID"
    ):
        store.prepare_poc_placeholder_exhaustion_replay(exhausted, artifacts)


def test_placeholder_replay_rejects_tampered_candidate_input_hash(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _placeholder_exhaustion(tmp_path)
    tampered = exhausted.model_copy(update={"input_hash": "0" * 64})
    store.save_checkpoint(tampered)

    with pytest.raises(ValueError, match="POC_PLACEHOLDER_EXHAUSTION_INVALID"):
        store.prepare_poc_placeholder_exhaustion_replay(tampered, artifacts)


def test_placeholder_replay_rejects_later_execution_checkpoint(tmp_path: Path) -> None:
    store, artifacts, exhausted = _placeholder_exhaustion(tmp_path)
    store.save_checkpoint(
        _checkpoint(
            exhausted.identity,
            SimpleStage.POC_EXECUTION_DONE,
            status=StageStatus.BLOCKED,
            attempt_id="candidate-attempt-3",
            attempt_number=3,
        )
    )
    with pytest.raises(ValueError, match="POC_PLACEHOLDER_EXHAUSTION_LINEAGE_INVALID"):
        store.prepare_poc_placeholder_exhaustion_replay(exhausted, artifacts)


def test_placeholder_replay_rejects_extra_same_attempt_event(tmp_path: Path) -> None:
    store, artifacts, exhausted = _placeholder_exhaustion(tmp_path)
    ledger = AgentActivityStore(store.database_path)
    started = next(
        event
        for event in ledger.list_analysis(
            exhausted.identity.analysis_id,
            hypothesis_id=exhausted.identity.hypothesis_id,
        )
        if event.stage == SimpleStage.POC_CANDIDATE_DONE.value
        and event.attempt_id == exhausted.attempt_id
        and event.kind is ActivityKind.STAGE_STARTED
    )
    ledger.append(
        started.model_copy(
            update={"event_id": uuid4().hex, "sequence": started.sequence + 500}
        )
    )
    with pytest.raises(ValueError, match="POC_PLACEHOLDER_EXHAUSTION_EVENT_INVALID"):
        store.prepare_poc_placeholder_exhaustion_replay(exhausted, artifacts)


def test_placeholder_replay_rejects_unresolved_codex_call(tmp_path: Path) -> None:
    store, artifacts, exhausted = _placeholder_exhaustion(tmp_path)
    assert store.begin_codex_call("unresolved-call", exhausted.identity.analysis_id)
    with pytest.raises(ValueError, match="POC_PLACEHOLDER_EXHAUSTION_CODEX_UNRESOLVED"):
        store.prepare_poc_placeholder_exhaustion_replay(exhausted, artifacts)


def test_placeholder_replay_rolls_back_checkpoint_and_marker_together(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _placeholder_exhaustion(tmp_path)
    ledger = AgentActivityStore(store.database_path)
    before = ledger.list_analysis(
        exhausted.identity.analysis_id, hypothesis_id=exhausted.identity.hypothesis_id
    )
    with pytest.raises(RuntimeError, match="simulated crash"):
        store.prepare_poc_placeholder_exhaustion_replay(
            exhausted, artifacts, fail_before_commit=True
        )
    assert store.require(exhausted.identity, exhausted.stage) == exhausted
    assert (
        ledger.list_analysis(
            exhausted.identity.analysis_id,
            hypothesis_id=exhausted.identity.hypothesis_id,
        )
        == before
    )


@pytest.mark.asyncio
async def test_application_requires_explicit_placeholder_replay_and_pinned_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _artifacts, exhausted = _placeholder_exhaustion(tmp_path)
    identity = exhausted.identity
    AnalysisDisplayIdStore(store.database_path).get_or_allocate(identity.analysis_id)
    application = SimpleAnalysisApplication(
        data_dir=tmp_path / "data",
        store=store,
        static_bootstrap=_PinnedStaticStub(tmp_path / "data" / "workspaces"),
        hypothesis_bootstrap=None,  # type: ignore[arg-type]
        runner_factory=None,  # type: ignore[arg-type]
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
    assert store.require(identity, SimpleStage.POC_CANDIDATE_DONE) == exhausted
    await application.resume(
        identity.analysis_id,
        repair_poc_placeholder_exhaustion_hypothesis=identity.hypothesis_id,
    )
    assert (
        store.require(identity, SimpleStage.POC_CANDIDATE_DONE).status
        is StageStatus.PENDING
    )


def test_cli_forwards_explicit_placeholder_replay_flag(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    class _Application(_PublicApplication):
        def __init__(self) -> None:
            self.seen: list[tuple[str, str | None]] = []

        def resume(
            self,
            analysis_id: str,
            *,
            repair_poc_placeholder_exhaustion_hypothesis: str | None = None,
            **_kwargs: object,
        ) -> dict[str, object]:
            self.seen.append(("plain", repair_poc_placeholder_exhaustion_hypothesis))
            return {"analysis_id": analysis_id, "status": "RUNNING"}

        def resume_with_progress(
            self,
            analysis_id: str,
            _callback: object,
            *,
            repair_poc_placeholder_exhaustion_hypothesis: str | None = None,
            **_kwargs: object,
        ) -> dict[str, object]:
            self.seen.append(("progress", repair_poc_placeholder_exhaustion_hypothesis))
            return {"analysis_id": analysis_id, "status": "RUNNING"}

    application = _Application()
    for extra, label in [(["--format", "json"], "plain"), ([], "progress")]:
        assert main(
            [
                "resume",
                "A-001",
                "--repair-poc-placeholder-exhaustion",
                "hypothesis-1",
                *extra,
            ],
            public_application=application,
            user_config_store=_config(tmp_path),
        ) == int(ExitCode.OK)
        assert application.seen[-1] == (label, "hypothesis-1")
        capsys.readouterr()
