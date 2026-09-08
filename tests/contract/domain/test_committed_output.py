import pytest

from sastsimi.contracts.static import (
    CodeWorkspace,
    StaticFactBundle,
    validate_static_current,
)
from sastsimi.contracts.work import (
    TransitionCommit,
    WorkAttempt,
    WorkExecutionState,
    WorkType,
)

from .canonical_fixtures import NOW, make
from .fixtures import bundle, meta, ref, wire
from .success_fixture import bound


def test_normalized_bundle_requires_exact_committed_output_attempt_and_work() -> None:
    from sastsimi.contracts.closure import validate_committed_output

    result = wire(StaticFactBundle, bundle())
    result_ref = bound(result)
    attempt = wire(
        WorkAttempt,
        make("WorkAttempt")
        | dict(
            meta=meta("work_attempt"),
            work_id="work1",
            attempt_id="at1",
            attempt_number=1,
            status="SUCCEEDED",
            input_hash="a" * 64,
            trigger="INITIAL",
            output_refs=[result_ref],
            finished_at=NOW,
        ),
    )
    commit = wire(
        TransitionCommit,
        make("TransitionCommit")
        | dict(
            meta=meta("transition_commit"),
            work_id="work1",
            expected_state_version=1,
            target_state_version=2,
            target_status="SUCCEEDED",
            state="COMMITTED",
            attempt_id="at1",
            output_refs=[result_ref],
            committed_at=NOW,
            transition_ref=ref("state_transition"),
        ),
    )
    work = wire(
        WorkExecutionState,
        make("WorkExecutionState")
        | dict(
            meta=meta("work_execution_state", attempt=None),
            work_id="work1",
            work_type="STATIC_NORMALIZE",
            subject_type="ANALYSIS",
            subject_id="a1",
            status="SUCCEEDED",
            state_version=2,
            input_hash="a" * 64,
            dedupe_key="b" * 64,
            output_refs=[result_ref],
            last_transition_ref=ref("state_transition"),
            last_transition_commit_ref=bound(commit),
            stop_reason="COMPLETED",
            finished_at=NOW,
        ),
    )
    from sastsimi.contracts.refs import StoredDataRef

    reference = wire(StoredDataRef, result_ref)
    validate_committed_output(
        result,
        reference,
        work,
        attempt,
        commit,
        expected_work_type=WorkType.STATIC_NORMALIZE,
    )
    workspace = wire(
        CodeWorkspace,
        make("CodeWorkspace")
        | dict(status="READY", analysis_id="a1", workspace_id="ws1", commit_id="c1"),
    )
    validate_static_current(
        result, reference, workspace, work, commit, (), attempt=attempt
    )
    with pytest.raises(ValueError, match="RESULT_WORK_ATTEMPT_MISMATCH"):
        validate_static_current(
            result,
            reference,
            workspace,
            work,
            commit,
            (),
            attempt=wire(
                WorkAttempt,
                attempt.model_dump(mode="json")
                | dict(attempt_id="old", meta=meta("work_attempt", attempt="old")),
            ),
        )
    for patch in (
        dict(state="PREPARED", committed_at=None),
        dict(work_id="other"),
        dict(attempt_id="old"),
    ):
        with pytest.raises(ValueError):
            validate_committed_output(
                result,
                reference,
                work,
                attempt,
                wire(TransitionCommit, commit.model_dump(mode="json") | patch),
                expected_work_type=WorkType.STATIC_NORMALIZE,
            )
